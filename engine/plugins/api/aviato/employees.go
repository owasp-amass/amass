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
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
)

func (ae *employees) check(e *et.Event) error {
	oamid, ok := e.Entity.Asset.(*general.Identifier)
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
		string(oam.Identifier), string(oam.Identifier), ae.plugin.name)
	if err != nil {
		return err
	}

	var orgent *dbt.Entity
	var employents []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, ae.plugin.source, since) {
		orgent, employents = ae.lookup(e, e.Entity, since)
	} else {
		orgent, employents = ae.query(e, e.Entity, keys)
		support.MarkAssetMonitored(e.Session, e.Entity, ae.plugin.source)
	}

	if orgent != nil && len(employents) > 0 {
		ae.process(e, orgent, employents)
	}
	return nil
}

func (ae *employees) lookup(e *et.Event, ident *dbt.Entity, since time.Time) (*dbt.Entity, []*dbt.Entity) {
	var orgent *dbt.Entity

	if edges, err := e.Session.Cache().IncomingEdges(ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, ae.plugin.source.Name); err != nil || len(tags) == 0 {
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

	var employents []*dbt.Entity
	if orgent == nil {
		return nil, employents
	}

	if edges, err := e.Session.Cache().OutgoingEdges(orgent, since, "member"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, ae.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*people.Person); ok {
					employents = append(employents, a)
				}
			}
		}
	}

	return orgent, employents
}

func (ae *employees) query(e *et.Event, ident *dbt.Entity, apikey []string) (*dbt.Entity, []*dbt.Entity) {
	oamid := e.Entity.Asset.(*general.Identifier)

	page := 1
	perPage := 50
	var total int
	var employlist []*employeeResult
loop:
	for _, key := range apikey {
		for p := page; ; p++ {
			headers := http.Header{"Content-Type": []string{"application/json"}}
			headers["Authorization"] = []string{"Bearer " + key}

			_ = ae.plugin.rlimit.Wait(context.TODO())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			u := fmt.Sprintf("https://data.api.aviato.co/company/%s/employees?perPage=%d&page=%d", oamid.ID, perPage, p)
			resp, err := http.RequestWebPage(ctx, &http.Request{URL: u, Header: headers})
			if err != nil || resp.StatusCode != 200 {
				continue
			}

			var result employeesResult
			if err := json.Unmarshal([]byte(resp.Body), &result); err != nil || len(result.Employees) == 0 {
				break loop
			}

			for _, emp := range result.Employees {
				employlist = append(employlist, &emp)
			}

			if len(employlist) >= 100 {
				break loop
			}

			page = p
			total = result.Pages
			if p >= total {
				break loop
			}
		}
	}

	if len(employlist) == 0 {
		return nil, []*dbt.Entity{}
	}

	return ae.store(e, ident, employlist)
}

func (ae *employees) store(e *et.Event, ident *dbt.Entity, employlist []*employeeResult) (*dbt.Entity, []*dbt.Entity) {
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

	var employents []*dbt.Entity
	if orgent == nil {
		return nil, employents
	}

	for _, emp := range employlist {
		p := support.FullNameToPerson(emp.Person.FullName)
		if p == nil {
			continue
		}

		personent, err := e.Session.Cache().CreateAsset(p)
		if err != nil || personent == nil {
			continue
		}

		_, _ = e.Session.Cache().CreateEntityProperty(ident, &general.SourceProperty{
			Source:     ae.plugin.source.Name,
			Confidence: 90,
		})

		if err := ae.plugin.createRelation(e.Session, orgent, general.SimpleRelation{Name: "member"}, personent, 90); err == nil {
			employents = append(employents, personent)
		}
	}

	return orgent, employents
}

func (ae *employees) process(e *et.Event, orgent *dbt.Entity, employents []*dbt.Entity) {
	for _, employee := range employents {
		p := employee.Asset.(*people.Person)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fmt.Sprintf("%s:%s", p.FullName, p.ID),
			Entity:  employee,
			Session: e.Session,
		})

		o := orgent.Asset.(*org.Organization)
		e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", "member",
			"to", p.FullName, slog.Group("plugin", "name", ae.plugin.name, "handler", ae.name))
	}
}
