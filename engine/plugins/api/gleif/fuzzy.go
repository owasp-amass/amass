// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

func (fc *fuzzyCompletions) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*org.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Organization), string(oam.Organization), fc.name)
	if err != nil {
		return err
	}

	var id *dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, fc.plugin.source, since) {
		id = fc.lookup(e, e.Entity, since)
	} else {
		id = fc.query(e, e.Entity)
		support.MarkAssetMonitored(e.Session, e.Entity, fc.plugin.source)
	}

	if id != nil {
		fc.process(e, e.Entity, id)
	}
	return nil
}

func (fc *fuzzyCompletions) lookup(e *et.Event, o *dbt.Entity, since time.Time) *dbt.Entity {
	var ids []*dbt.Entity

	if edges, err := e.Session.Cache().OutgoingEdges(o, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge,
				since, fc.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*general.Identifier); ok {
					ids = append(ids, a)
				}
			}
		}
	}

	for _, ident := range ids {
		if id := ident.Asset.(*general.Identifier); id != nil && id.Type == general.LEICode {
			return ident
		}
	}
	return nil
}

func (fc *fuzzyCompletions) query(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
	exclusive := true
	var leiList []*general.Identifier

	if leient := fc.plugin.orgEntityToLEI(e, orgent); leient != nil {
		leiList = append(leiList, leient.Asset.(*general.Identifier))
	}

	if len(leiList) == 0 {
		o := orgent.Asset.(*org.Organization)
		u := "https://api.gleif.org/api/v1/fuzzycompletions?field=fulltext&q=" + url.QueryEscape(o.Name)

		fc.plugin.rlimit.Take()
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
		if err != nil || resp.Body == "" {
			return nil
		}

		var result struct {
			Data []struct {
				Type       string `json:"type"`
				Attributes struct {
					Value string `json:"value"`
				} `json:"attributes"`
				Relationships struct {
					LEIRecords struct {
						Data struct {
							Type string `json:"type"`
							ID   string `json:"id"`
						} `json:"data"`
						Links struct {
							Related string `json:"related"`
						} `json:"links"`
					} `json:"lei-records"`
				} `json:"relationships"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil || len(result.Data) == 0 {
			return nil
		}
		exclusive = len(result.Data) == 1

		for _, d := range result.Data {
			if fc.nameMatch(o, d.Attributes.Value) {
				leiList = append(leiList, &general.Identifier{
					UniqueID: fmt.Sprintf("%s:%s", general.LEICode, d.Relationships.LEIRecords.Data.ID),
					EntityID: d.Relationships.LEIRecords.Data.ID,
					Type:     general.LEICode,
				})
				break
			}
		}
		if len(leiList) == 0 {
			return nil
		}
	}

	var rec *leiRecord
	for _, lei := range leiList {
		r, err := fc.plugin.getLEIRecord(lei)
		if err == nil && (exclusive || fc.locMatch(e, orgent, rec)) {
			rec = r
			break
		}
	}
	if rec == nil {
		return nil
	}

	return fc.store(e, orgent, rec)
}

func (fc *fuzzyCompletions) nameMatch(o *org.Organization, name string) bool {
	if strings.EqualFold(o.Name, name) {
		return true
	}

	swg := metrics.NewSmithWatermanGotoh()
	swg.CaseSensitive = false
	swg.GapPenalty = -0.1
	swg.Substitution = metrics.MatchMismatch{
		Match:    1,
		Mismatch: -0.5,
	}

	return strutil.Similarity(o.Name, name, swg) >= 0.85
}

func (fc *fuzzyCompletions) locMatch(e *et.Event, orgent *dbt.Entity, rec *leiRecord) bool {
	legal_addr := rec.Attributes.Entity.LegalAddress
	hq_addr := rec.Attributes.Entity.HeadquartersAddress

	if edges, err := e.Session.Cache().OutgoingEdges(orgent,
		time.Time{}, "legal_address", "hq_address", "location"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if loc, ok := a.Asset.(*contact.Location); ok {
					for _, p := range append([]leiAddress{legal_addr, hq_addr}, rec.Attributes.Entity.OtherAddresses...) {
						if loc.PostalCode == p.PostalCode {
							return true
						}
					}
				}
			}
		}
	}

	var crs []*dbt.Entity
	if edges, err := e.Session.Cache().IncomingEdges(orgent, time.Time{}, "organization"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*contact.ContactRecord); ok {
					crs = append(crs, a)
				}
			}
		}
	}

	for _, cr := range crs {
		if edges, err := e.Session.Cache().OutgoingEdges(cr, time.Time{}, "location"); err == nil {
			for _, edge := range edges {
				if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
					if loc, ok := a.Asset.(*contact.Location); ok {
						for _, p := range append([]leiAddress{legal_addr, hq_addr}, rec.Attributes.Entity.OtherAddresses...) {
							if loc.PostalCode == p.PostalCode {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func (fc *fuzzyCompletions) store(e *et.Event, orgent *dbt.Entity, rec *leiRecord) *dbt.Entity {
	fc.plugin.updateOrgFromLEIRecord(e, orgent, rec)

	ident, err := fc.plugin.createLEIFromRecord(e, orgent, rec)
	if err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
		return nil
	}

	return ident
}

func (fc *fuzzyCompletions) process(e *et.Event, orgent, ident *dbt.Entity) {
	id := ident.Asset.(*general.Identifier)

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    id.UniqueID,
		Entity:  ident,
		Session: e.Session,
	})

	o := orgent.Asset.(*org.Organization)
	e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", "id",
		"to", id.UniqueID, slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
}
