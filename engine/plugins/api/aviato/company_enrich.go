// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func (ce *companyEnrich) check(e *et.Event) error {
	oamid, ok := e.Entity.Asset.(*oamgen.Identifier)
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
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().IncomingEdges(ctx, ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, ce.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					return a
				}
			}
		}
	}
	return nil
}

func (ce *companyEnrich) query(e *et.Event, ident *dbt.Entity, apikey []string) (*dbt.Entity, *companyEnrichResult) {
	oamid := e.Entity.Asset.(*oamgen.Identifier)

	orgent := ce.lookup(e, ident, time.Time{})
	if orgent == nil {
		msg := fmt.Sprintf("failed to find the Organization asset for %s", oamid.UniqueID)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
		return nil, nil
	}

	var enrich *companyEnrichResult
	for _, key := range apikey {
		headers := amasshttp.Header{"Content-Type": []string{"application/json"}}
		headers["Authorization"] = []string{"Bearer " + key}

		_ = ce.plugin.rlimit.Wait(e.Session.Ctx())
		e.Session.NetSem().Acquire()

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
		defer cancel()

		u := fmt.Sprintf("https://data.api.aviato.co/company/enrich?id=%s", url.QueryEscape(oamid.ID))
		resp, err := amasshttp.RequestWebPage(ctx,
			e.Session.Clients().General, &amasshttp.Request{URL: u, Header: headers})
		e.Session.NetSem().Release()
		if err != nil {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: %s", oamid.ID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		} else if resp.StatusCode != 200 {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: %s", oamid.ID, resp.Status)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		} else if resp.Body == "" {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: empty body", oamid.ID)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		} else if strings.Contains(resp.Body, "error") {
			msg := fmt.Sprintf("failed to obtain the company enrich result for %s: %s", oamid.ID, resp.Body)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			continue
		}

		var result companyEnrichResult
		if err := json.Unmarshal([]byte(resp.Body), &result); err == nil {
			enrich = &result
		} else {
			msg := fmt.Sprintf("failed to unmarshal the company enrich result for %s: %s", oamid.ID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
		}
		break
	}

	if enrich == nil {
		return nil, nil
	}
	return orgent, enrich
}

func (ce *companyEnrich) store(e *et.Event, orgent *dbt.Entity, data *companyEnrichResult) {
	o := orgent.Asset.(*oamorg.Organization)

	o.Active = false
	if strings.EqualFold(data.Status, "active") {
		o.Active = true
	}
	o.NonProfit = data.IsNonProfit
	o.Headcount = data.Headcount

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	// attempt to set the legal name
	if o.LegalName == "" && data.LegalName != "" {
		o.LegalName = data.LegalName

		oamid := &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", oamgen.LegalName, o.LegalName),
			ID:       o.LegalName,
			Type:     oamgen.LegalName,
		}

		ident, err := e.Session.DB().CreateAsset(ctx, oamid)
		if err != nil || ident == nil {
			msg := fmt.Sprintf("failed to create the Identifier asset for %s: %s", o.LegalName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			return
		}

		_, err = e.Session.DB().CreateEntityProperty(ctx, ident, &oamgen.SourceProperty{
			Source:     ce.name,
			Confidence: ce.plugin.source.Confidence,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create the SourceProperty for %s: %s", o.LegalName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			_ = e.Session.DB().DeleteEntity(ctx, ident.ID)
			return
		}

		err = ce.plugin.createRelation(ctx, e.Session, orgent, oamgen.SimpleRelation{Name: "id"}, ident, ce.plugin.source.Confidence)
		if err != nil {
			msg := fmt.Sprintf("failed to create the relation for %s: %s", o.LegalName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
			_ = e.Session.DB().DeleteEntity(ctx, ident.ID)
			return
		}
	}
	// update entity
	_, err := e.Session.DB().CreateEntity(ctx, orgent)
	if err != nil {
		msg := fmt.Sprintf("failed to update the Organization asset for %s: %s", o.Name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
		return
	}
}

func (ce *companyEnrich) process(e *et.Event, ident, orgent *dbt.Entity) {
	o := orgent.Asset.(*oamorg.Organization)

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
		Entity:  orgent,
		Session: e.Session,
	})

	id := ident.Asset.(*oamgen.Identifier)
	e.Session.Log().Info("relationship discovered", "from", id.UniqueID, "relation", "id",
		"to", o.Name, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
}
