// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package expansion

import (
	"errors"
	"log/slog"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/owasp-amass/open-asset-model/relation"
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
		EventType:  oam.EmailAddress,
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
	_, ok := e.Entity.Asset.(*contact.EmailAddress)
	if !ok {
		return errors.New("failed to extract the EmailAddress asset")
	}

	if findings := ee.store(e, e.Entity); len(findings) > 0 {
		ee.process(e, findings)
	}
	return nil
}

func (ee *emailexpand) store(e *et.Event, asset *dbt.Entity) []*support.Finding {
	var findings []*support.Finding
	oame := asset.Asset.(*contact.EmailAddress)

	if a, err := e.Session.Cache().CreateAsset(&domain.FQDN{Name: oame.Domain}); err == nil && a != nil {
		findings = append(findings, &support.Finding{
			From:     asset,
			FromName: "EmailAddress: " + asset.Asset.Key(),
			To:       a,
			ToName:   a.Asset.Key(),
			Rel:      &relation.SimpleRelation{Name: "domain"},
		})
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
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
				Source:     ee.source.Name,
				Confidence: ee.source.Confidence,
			})
		}
	}
}
