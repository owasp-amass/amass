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
	oampeop "github.com/owasp-amass/open-asset-model/people"
)

func (ae *employees) check(e *et.Event) error {
	oamid, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	} else if oamid.Type != AviatoCompanyID {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(ae.plugin.name)
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
		string(oam.Identifier), string(oam.Person), ae.plugin.name)
	if err != nil {
		return err
	}

	if ae.plugin.identOrg(e, e.Entity) == nil {
		return nil
	}

	var orgent *dbt.Entity
	var employents []*dbt.Entity
	src := &et.Source{
		Name:       ae.name,
		Confidence: ae.plugin.source.Confidence,
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		orgent, employents = ae.lookup(e, e.Entity, since)
	} else {
		orgent, employents = ae.query(e, e.Entity, keys)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if orgent != nil && len(employents) > 0 {
		ae.process(e, orgent, employents)
	}
	return nil
}

func (ae *employees) lookup(e *et.Event, ident *dbt.Entity, since time.Time) (*dbt.Entity, []*dbt.Entity) {
	var orgent *dbt.Entity

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().IncomingEdges(ctx, ident, since, "id"); err == nil {
		for _, edge := range edges {
			if !support.Sourced(ctx, e.Session, edge, since, ae.plugin.source) {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					orgent = a
					break
				}
			}
		}
	}

	var employents []*dbt.Entity
	if orgent == nil {
		return nil, employents
	}

	if edges, err := e.Session.DB().OutgoingEdges(ctx, orgent, since, "member"); err == nil {
		for _, edge := range edges {
			if !support.Sourced(ctx, e.Session, edge, since, ae.plugin.source) {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oampeop.Person); ok {
					employents = append(employents, a)
				}
			}
		}
	}

	return orgent, employents
}

func (ae *employees) query(e *et.Event, ident *dbt.Entity, apikey []string) (*dbt.Entity, []*dbt.Entity) {
	oamid := e.Entity.Asset.(*oamgen.Identifier)

	orgent := ae.plugin.identOrg(e, ident)
	if orgent == nil {
		msg := fmt.Sprintf("failed to find the Organization asset for %s", oamid.UniqueID)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
		return nil, []*dbt.Entity{}
	}

	page := 0
	total := 1
	perPage := 1000
	var employents []*dbt.Entity
loop:
	for _, key := range apikey {
		for ; page < total; page++ {
			headers := amasshttp.Header{"Content-Type": []string{"application/json"}}
			headers["Authorization"] = []string{"Bearer " + key}

			_ = support.WaitLimit(e.Session.Ctx(), ae.plugin.rlimit)
			e.Session.NetSem().Acquire()

			ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
			defer cancel()

			u := fmt.Sprintf("%s/company/%s/employees?perPage=%d&page=%d", ae.plugin.api,
				url.QueryEscape(oamid.ID), perPage, page)
			resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u, Header: headers})
			e.Session.NetSem().Release()
			if err != nil {
				msg := fmt.Sprintf("failed to obtain the employees for %s: %s", oamid.ID, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
				// try the next key for the same page
				continue loop
			} else if resp.StatusCode != 200 {
				msg := fmt.Sprintf("failed to obtain the employees for %s: %s", oamid.ID, resp.Status)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
				continue loop
			} else if resp.Body == "" {
				msg := fmt.Sprintf("failed to obtain the employees for %s: empty body", oamid.ID)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
				continue loop
			} else if strings.Contains(resp.Body, `"error"`) {
				msg := fmt.Sprintf("failed to obtain the employees for %s: %s", oamid.ID, resp.Body)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
				continue loop
			}

			var result employeesResult
			if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
				msg := fmt.Sprintf("failed to unmarshal the employees for %s: %s", oamid.ID, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
				break loop
			} else if len(result.Employees) == 0 {
				break loop
			}

			if len(result.Employees) > 0 {
				if ents := ae.store(e, ident, orgent, result.Employees); len(ents) > 0 {
					employents = append(employents, ents...)
				}
			}

			total = result.Pages
		}

		if page >= total {
			break
		}
	}

	if len(employents) == 0 {
		return nil, []*dbt.Entity{}
	}
	return orgent, employents
}

func (ae *employees) store(e *et.Event, ident, orgent *dbt.Entity, employlist []employeeResult) []*dbt.Entity {
	var employents []*dbt.Entity

	for _, emp := range employlist {
		p := support.ListedPerson(emp.Person.FullName)
		if p == nil {
			continue
		}

		personent, err := support.CreatePersonAsset(e.Session, orgent,
			&oamgen.SimpleRelation{Name: "member"}, p, ae.plugin.source)
		if err != nil {
			msg := fmt.Sprintf("failed to create the Person asset for %s: %s", p.FullName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
			continue
		}

		employents = append(employents, personent)
	}

	return employents
}

func (ae *employees) process(e *et.Event, orgent *dbt.Entity, employents []*dbt.Entity) {
	for _, employee := range employents {
		p := employee.Asset.(*oampeop.Person)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fmt.Sprintf("%s:%s", p.FullName, p.ID),
			Entity:  employee,
			Session: e.Session,
		})

		o := orgent.Asset.(*oamorg.Organization)
		e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", "member",
			"to", p.FullName, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
	}
}
