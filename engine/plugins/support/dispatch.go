// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
)

type Finding struct {
	From     *dbt.Entity
	FromName string
	To       *dbt.Entity
	ToName   string
	ToMeta   interface{}
	Rel      oam.Relation
}

func ProcessAssetsWithSource(e *et.Event, findings []*Finding, src *et.Source, pname, hname string) {
	for _, finding := range findings {
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    finding.ToName,
			Meta:    finding.ToMeta,
			Entity:  finding.To,
			Session: e.Session,
		})

		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   finding.Rel,
			FromEntity: finding.From,
			ToEntity:   finding.To,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
			e.Session.Log().Info("relationship discovered", "from", finding.FromName, "relation",
				finding.Rel, "to", finding.ToName, slog.Group("plugin", "name", pname, "handler", hname))
		}
	}
}

func ProcessFQDNsWithSource(e *et.Event, entities []*dbt.Entity, src *et.Source) {
	for _, entity := range entities {
		fqdn, ok := entity.Asset.(*domain.FQDN)
		if !ok || fqdn == nil {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fqdn.Name,
			Entity:  entity,
			Session: e.Session,
		})

		_, _ = e.Session.Cache().CreateEntityProperty(entity, &property.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
	}
}

func ProcessEmailsWithSource(e *et.Event, entities []*dbt.Entity, src *et.Source) {
	for _, entity := range entities {
		email, ok := entity.Asset.(*contact.EmailAddress)
		if !ok || email == nil {
			continue
		}

		if _, conf := e.Session.Scope().IsAssetInScope(email, 0); conf == 0 {
			continue
		}

		meta := e.Meta
		if meta == nil {
			meta = &et.EmailMeta{
				VerifyAttempted: false,
				Verified:        false,
			}
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    email.Address,
			Meta:    meta,
			Entity:  entity,
			Session: e.Session,
		})

		_, _ = e.Session.Cache().CreateEntityProperty(entity, &property.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
	}
}
