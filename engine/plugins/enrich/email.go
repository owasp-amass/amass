// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"log/slog"
	"strings"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

type emailexpand struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewEmails() et.Plugin {
	return &emailexpand{
		name: "Email-Expansion",
		source: &et.Source{
			Name:       "Email-Expansion",
			Confidence: 100,
		},
	}
}

func (ee *emailexpand) Name() string {
	return ee.name
}

func (ee *emailexpand) Start(r et.Registry) error {
	ee.log = r.Log().WithGroup("plugin").With("name", ee.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     ee,
		Name:       ee.name,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.Identifier,
		Callback:   ee.check,
	}); err != nil {
		return err
	}

	ee.log.Info("Plugin started")
	return nil
}

func (ee *emailexpand) Stop() {
	ee.log.Info("Plugin stopped")
}

func (ee *emailexpand) check(e *et.Event) error {
	if id, ok := e.Entity.Asset.(*general.Identifier); !ok ||
		id == nil || id.Type != general.EmailAddress || id.ID == "" {
		return nil
	}

	if findings := ee.store(e, e.Entity); len(findings) > 0 {
		ee.process(e, findings)
	}
	return nil
}

func (ee *emailexpand) store(e *et.Event, asset *dbt.Entity) []*support.Finding {
	var findings []*support.Finding
	oame := asset.Asset.(*general.Identifier)

	parts := strings.Split(oame.ID, "@")
	if len(parts) != 2 {
		return findings
	}
	domain := parts[1]

	if cr, err := e.Session.Cache().CreateAsset(&contact.ContactRecord{DiscoveredAt: domain}); err == nil && cr != nil {
		findings = append(findings, &support.Finding{
			From:     asset,
			FromName: "Identifier: " + asset.Asset.Key(),
			To:       cr,
			ToName:   "ContactRecord: " + cr.Asset.Key(),
			Rel:      &general.SimpleRelation{Name: "registration_agency"},
		})

		if a, err := e.Session.Cache().CreateAsset(&oamdns.FQDN{Name: domain}); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From:     cr,
				FromName: "ContactRecord: " + cr.Asset.Key(),
				To:       a,
				ToName:   a.Asset.Key(),
				Rel:      &general.SimpleRelation{Name: "fqdn"},
			})
		}
	}

	return findings
}

func (ee *emailexpand) process(e *et.Event, findings []*support.Finding) {
	for _, f := range findings {
		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   f.Rel,
			FromEntity: f.From,
			ToEntity:   f.To,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
				Source:     ee.source.Name,
				Confidence: ee.source.Confidence,
			})
		}
	}
}
