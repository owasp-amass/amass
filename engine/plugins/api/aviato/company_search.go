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
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

func (cs *companySearch) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*org.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(cs.plugin.name)
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
		string(oam.Organization), string(oam.Identifier), cs.plugin.name)
	if err != nil {
		return err
	}

	var id *dbt.Entity
	src := &et.Source{
		Name:       cs.name,
		Confidence: cs.plugin.source.Confidence,
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		id = cs.lookup(e, e.Entity, since)
	} else {
		id = cs.query(e, e.Entity, keys)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if id != nil {
		cs.process(e, e.Entity, id)
	}
	return nil
}

func (cs *companySearch) lookup(e *et.Event, orgent *dbt.Entity, since time.Time) *dbt.Entity {
	if edges, err := e.Session.Cache().OutgoingEdges(orgent, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge,
				since, cs.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*general.Identifier); ok && id != nil && id.Type == AviatoCompanyID {
					return a
				}
			}
		}
	}
	return nil
}

func (cs *companySearch) query(e *et.Event, orgent *dbt.Entity, apikey []string) *dbt.Entity {
	o := orgent.Asset.(*org.Organization)
	brand := support.ExtractBrandName(o.Name)

	var body string
	success := false
	for _, key := range apikey {
		headers := http.Header{"Content-Type": []string{"application/json"}}
		headers["Authorization"] = []string{"Bearer " + key}

		_ = cs.plugin.rlimit.Wait(context.TODO())
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		filters := []map[string]*dslEvalObj{
			{
				"name": &dslEvalObj{
					Operation: "eq",
					Value:     brand,
				},
			},
		}

		reqDSL := &dsl{
			Offset:  0,
			Limit:   10,
			Filters: filters,
		}

		dslJSON, err := json.Marshal(reqDSL)
		if err != nil {
			return nil
		}

		if resp, err := http.RequestWebPage(ctx, &http.Request{
			URL:    "https://data.api.aviato.co/company/search",
			Method: "POST",
			Header: headers,
			Body:   `{"dsl": ` + string(dslJSON) + `}`,
		}); err == nil {
			if resp.StatusCode == 200 {
				success = true
				body = resp.Body
				break
			} else {
				msg := fmt.Sprintf("failed to obtain the company search result for %s: %s", o.Name, resp.Status)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cs.plugin.name, "handler", cs.name))
			}
		} else {
			msg := fmt.Sprintf("failed to obtain the company search result for %s: %s", o.Name, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cs.plugin.name, "handler", cs.name))
		}
	}

	if !success {
		return nil
	}

	var result companySearchResult
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		msg := fmt.Sprintf("failed to unmarshal the company search result for %s: %s", o.Name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cs.plugin.name, "handler", cs.name))
		return nil
	} else if len(result.Items) == 0 {
		return nil
	}

	return cs.store(e, orgent, result.Items[0].ID)
}

func (cs *companySearch) store(e *et.Event, orgent *dbt.Entity, companyID string) *dbt.Entity {
	oamid := &general.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", AviatoCompanyID, companyID),
		ID:       companyID,
		Type:     AviatoCompanyID,
	}

	ident, err := e.Session.Cache().CreateAsset(oamid)
	if err != nil || ident == nil {
		msg := fmt.Sprintf("failed to create the identifier asset for %s: %s", companyID, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cs.plugin.name, "handler", cs.name))
		return nil
	}

	_, err = e.Session.Cache().CreateEntityProperty(ident, &general.SourceProperty{
		Source:     cs.name,
		Confidence: cs.plugin.source.Confidence,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to create the identifier source property for %s: %s", companyID, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cs.plugin.name, "handler", cs.name))
		return nil
	}

	if err := cs.plugin.createRelation(e.Session, orgent,
		general.SimpleRelation{Name: "id"}, ident, cs.plugin.source.Confidence); err != nil {
		msg := fmt.Sprintf("failed to create the identifier relation for %s: %s", companyID, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cs.plugin.name, "handler", cs.name))
		_ = e.Session.Cache().DeleteEntity(ident.ID)
		return nil
	}
	return ident
}

func (cs *companySearch) process(e *et.Event, orgent, ident *dbt.Entity) {
	id := ident.Asset.(*general.Identifier)

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    id.UniqueID,
		Entity:  ident,
		Session: e.Session,
	})

	o := orgent.Asset.(*org.Organization)
	e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", "id",
		"to", id.UniqueID, slog.Group("plugin", "name", cs.plugin.name, "handler", cs.name))
}
