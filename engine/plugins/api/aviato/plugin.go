// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

func NewAviato() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &aviato{
		name:   "Aviato",
		api:    "https://data.api.aviato.co",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Aviato",
			Confidence: 90,
		},
	}
}

func (a *aviato) Name() string {
	return a.name
}

func (a *aviato) Start(r et.Registry) error {
	a.log = r.Log().WithGroup("plugin").With("name", a.name)

	a.employees = &employees{
		name:   a.name + "-Employees-Handler",
		plugin: a,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.employees.name,
		Position:     41,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Person)},
		EventType:    oam.Identifier,
		Callback:     a.employees.check,
	}); err != nil {
		return err
	}

	a.companyRounds = &companyRounds{
		name:   a.name + "-Company-Rounds-Handler",
		plugin: a,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.companyRounds.name,
		Position:     42,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.Organization),
			string(oam.Account),
			string(oam.FundsTransfer),
		},
		EventType: oam.Identifier,
		Callback:  a.companyRounds.check,
	}); err != nil {
		return err
	}

	a.companyEnrich = &companyEnrich{
		name:   a.name + "-Company-Enrich-Handler",
		plugin: a,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.companyEnrich.name,
		Position:     43,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Organization)},
		EventType:    oam.Identifier,
		Callback:     a.companyEnrich.check,
	}); err != nil {
		return err
	}

	a.companySearch = &companySearch{
		name:   a.name + "-Company-Search-Handler",
		plugin: a,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.companySearch.name,
		Position:     41,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Identifier)},
		EventType:    oam.Organization,
		Callback:     a.companySearch.check,
	}); err != nil {
		return err
	}

	a.log.Info("Plugin started")
	return nil
}

func (a *aviato) Stop() {
	a.log.Info("Plugin stopped")
}

// identOrg returns the organization that links to the Aviato identifier.
func (a *aviato) identOrg(e *et.Event, ident *dbt.Entity) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().IncomingEdges(ctx, ident, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if ent, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && ent != nil {
				if _, ok := ent.Asset.(*oamorg.Organization); ok {
					return ent
				}
			}
		}
	}
	return nil
}
