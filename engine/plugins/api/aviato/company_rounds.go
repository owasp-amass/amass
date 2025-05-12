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
	"github.com/owasp-amass/open-asset-model/people"
)

func (cr *companyRounds) check(e *et.Event) error {
	oamid, ok := e.Entity.Asset.(*general.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	} else if oamid.Type != AviatoCompanyID {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(cr.plugin.name)
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
		string(oam.Identifier), string(oam.Organization), cr.plugin.name)
	if err != nil {
		return err
	}

	var orgent *dbt.Entity
	var fundents []*dbt.Entity
	src := &et.Source{
		Name:       cr.name,
		Confidence: cr.plugin.source.Confidence,
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		orgent, fundents = cr.lookup(e, e.Entity, since)
	} else {
		orgent, fundents = cr.query(e, e.Entity, keys)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if orgent != nil && len(fundents) > 0 {
		cr.process(e, orgent, fundents)
	}
	return nil
}

func (cr *companyRounds) lookup(e *et.Event, ident *dbt.Entity, since time.Time) (*dbt.Entity, []*dbt.Entity) {
	var orgent *dbt.Entity

	if edges, err := e.Session.Cache().IncomingEdges(ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, cr.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					orgent = a
					break
				}
			}
		}
	}

	var fundents []*dbt.Entity
	if orgent == nil {
		return nil, fundents
	}

	if edges, err := e.Session.Cache().OutgoingEdges(orgent, since, "member"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, cr.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*people.Person); ok {
					fundents = append(fundents, a)
				}
			}
		}
	}

	return orgent, fundents
}

func (cr *companyRounds) query(e *et.Event, ident *dbt.Entity, apikey []string) (*dbt.Entity, []*dbt.Entity) {
	oamid := e.Entity.Asset.(*general.Identifier)

	orgent := cr.getAssociatedOrg(e, ident)
	if orgent == nil {
		msg := fmt.Sprintf("failed to find the Organization asset for %s", oamid.UniqueID)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		return nil, []*dbt.Entity{}
	}

	page := 0
	total := 1
	perPage := 100
	var fundents []*dbt.Entity
loop:
	for _, key := range apikey {
		for ; page < total; page++ {
			headers := http.Header{"Content-Type": []string{"application/json"}}
			headers["Authorization"] = []string{"Bearer " + key}

			_ = cr.plugin.rlimit.Wait(context.TODO())
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			u := fmt.Sprintf("https://data.api.aviato.co/company/%s/funding-rounds?perPage=%d&page=%d", url.QueryEscape(oamid.ID), perPage, page)
			resp, err := http.RequestWebPage(ctx, &http.Request{URL: u, Header: headers})
			if err != nil {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
			} else if resp.StatusCode != 200 {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, resp.Status)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
			} else if resp.Body == "" {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: empty body", oamid.ID)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
			} else if strings.Contains(resp.Body, "error") {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, resp.Body)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
			}

			var result companyRoundsResult
			if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
				msg := fmt.Sprintf("failed to unmarshal the funding rounds for %s: %s", oamid.ID, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				break loop
			} else if len(result.FundingRounds) == 0 {
				break loop
			}

			if len(result.FundingRounds) > 0 {
				if ents := cr.store(e, ident, orgent, &result); len(ents) > 0 {
					fundents = append(fundents, ents...)
				}
			}

			total = result.Pages
		}

		if page >= total {
			break
		}
	}

	if len(fundents) == 0 {
		return nil, []*dbt.Entity{}
	}
	return orgent, fundents
}

func (cr *companyRounds) getAssociatedOrg(e *et.Event, ident *dbt.Entity) *dbt.Entity {
	var orgent *dbt.Entity

	if edges, err := e.Session.Cache().IncomingEdges(ident, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					orgent = a
					break
				}
			}
		}
	}

	return orgent
}

func (cr *companyRounds) store(e *et.Event, ident, orgent *dbt.Entity, funds *companyRoundsResult) []*dbt.Entity {
	var fundents []*dbt.Entity

	/*for _, round := range funds.FundingRounds {
		p := support.FullNameToPerson(emp.Person.FullName)
		if p == nil {
			continue
		}

		personent, err := e.Session.Cache().CreateAsset(p)
		if err != nil {
			msg := fmt.Sprintf("failed to create the Person asset for %s: %s", p.FullName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		_, err = e.Session.Cache().CreateEntityProperty(personent, &general.SourceProperty{
			Source:     cr.name,
			Confidence: cr.plugin.source.Confidence,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create the Person asset source property for %s: %s", p.FullName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		if err := cr.plugin.createRelation(e.Session, orgent,
			general.SimpleRelation{Name: "member"}, personent, cr.plugin.source.Confidence); err == nil {
			employents = append(employents, personent)
		} else {
			msg := fmt.Sprintf("failed to create the member relation for %s: %s", p.FullName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		}
	}*/

	return fundents
}

func (cr *companyRounds) process(e *et.Event, orgent *dbt.Entity, fundents []*dbt.Entity) {
	/*
		for _, fund := range fundents {
			p := employee.Asset.(*people.Person)

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fmt.Sprintf("%s:%s", p.FullName, p.ID),
				Entity:  employee,
				Session: e.Session,
			})

			o := orgent.Asset.(*org.Organization)
			e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", "member",
				"to", p.FullName, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		}
	*/
}
