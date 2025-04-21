// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

func (ce *companyEnrich) check(e *et.Event) error {
	oamid, ok := e.Entity.Asset.(*general.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	} else if oamid.Type != AviatoCompanyID {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(ce.plugin.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}
	if len(keys) == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Identifier), string(oam.Organization), ce.plugin.name)
	if err != nil {
		return err
	}

	var orgent *dbt.Entity
	src := &et.Source{
		Name:       ce.name,
		Confidence: ce.plugin.source.Confidence,
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		orgent = ce.lookup(e, e.Entity, since)
	} else if o, data := ce.query(e, e.Entity, keys); data != nil {
		orgent = o
		ce.store(e, o, data)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if orgent != nil {
		ce.process(e, e.Entity, orgent)
	}
	return nil
}

func (ce *companyEnrich) lookup(e *et.Event, ident *dbt.Entity, since time.Time) *dbt.Entity {
	if edges, err := e.Session.Cache().IncomingEdges(ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, ce.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					return a
				}
			}
		}
	}
	return nil
}

func (ce *companyEnrich) query(e *et.Event, ident *dbt.Entity, apikey []string) (*dbt.Entity, *companyEnrichResult) {
	oamid := e.Entity.Asset.(*general.Identifier)

	orgent := ce.lookup(e, ident, time.Time{})
	if orgent == nil {
		msg := fmt.Sprintf("failed to find the Organization asset for %s", oamid.UniqueID)
		e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
		return nil, nil
	}

	var enrich *companyEnrichResult
	for _, key := range apikey {
		headers := http.Header{"Content-Type": []string{"application/json"}}
		headers["Authorization"] = []string{"Bearer " + key}

		_ = ce.plugin.rlimit.Wait(context.TODO())
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		u := fmt.Sprintf("https://data.api.aviato.co/company/enrich?id=%s", url.QueryEscape(oamid.ID))
		resp, err := http.RequestWebPage(ctx, &http.Request{URL: u, Header: headers})
		if err != nil {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: %s", oamid.ID, err)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		} else if resp.StatusCode != 200 {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: %s", oamid.ID, resp.Status)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		} else if resp.Body == "" {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: empty body", oamid.ID)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		} else if strings.Contains(resp.Body, "error") {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: %s", oamid.ID, resp.Body)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		}

		var result companyEnrichResult
		if err := json.Unmarshal([]byte(resp.Body), &result); err == nil {
			enrich = &result
		} else {
			msg := fmt.Sprintf("failed to unmarshal the company enrich result for %s: %s", oamid.ID, err)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
		}
		break
	}

	if enrich == nil {
		return nil, nil
	}
	return orgent, enrich
}

func (ce *companyEnrich) store(e *et.Event, orgent *dbt.Entity, data *companyEnrichResult) {
	o := orgent.Asset.(*org.Organization)

	o.Active = false
	if strings.EqualFold(data.Status, "active") {
		o.Active = true
	}
	o.NonProfit = data.IsNonProfit
	o.Headcount = data.Headcount

	// attempt to set the legal name
	if o.LegalName == "" && data.LegalName != "" {
		o.LegalName = data.LegalName

		oamid := &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.LegalName, o.LegalName),
			ID:       o.LegalName,
			Type:     general.LegalName,
		}

		ident, err := e.Session.Cache().CreateAsset(oamid)
		if err != nil || ident == nil {
			msg := fmt.Sprintf("failed to create the Identifier asset for %s: %s", o.LegalName, err)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			return
		}

		_, err = e.Session.Cache().CreateEntityProperty(ident, &general.SourceProperty{
			Source:     ce.name,
			Confidence: ce.plugin.source.Confidence,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create the SourceProperty for %s: %s", o.LegalName, err)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			return
		}

		err = ce.plugin.createRelation(e.Session, orgent, general.SimpleRelation{Name: "id"}, ident, ce.plugin.source.Confidence)
		if err != nil {
			msg := fmt.Sprintf("failed to create the relation for %s: %s", o.LegalName, err)
			e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			return
		}
	}
	// update entity
	_, err := e.Session.Cache().CreateEntity(orgent)
	if err != nil {
		msg := fmt.Sprintf("failed to update the Organization asset for %s: %s", o.Name, err)
		e.Session.Log().Error("msg", msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
		return
	}
}

func (ce *companyEnrich) process(e *et.Event, ident, orgent *dbt.Entity) {
	o := orgent.Asset.(*org.Organization)

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
		Entity:  orgent,
		Session: e.Session,
	})

	id := ident.Asset.(*general.Identifier)
	e.Session.Log().Info("relationship discovered", "from", id.UniqueID, "relation", "id",
		"to", o.Name, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
}
