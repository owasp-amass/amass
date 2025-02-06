// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
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
		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   finding.Rel,
			FromEntity: finding.From,
			ToEntity:   finding.To,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    finding.ToName,
				Meta:    finding.ToMeta,
				Entity:  finding.To,
				Session: e.Session,
			})

			e.Session.Log().Info("relationship discovered", "from", finding.FromName, "relation",
				finding.Rel, "to", finding.ToName, slog.Group("plugin", "name", pname, "handler", hname))
		}
	}
}

func ProcessFQDNsWithSource(e *et.Event, entities []*dbt.Entity, src *et.Source) {
	for _, entity := range entities {
		fqdn, ok := entity.Asset.(*oamdns.FQDN)
		if !ok || fqdn == nil {
			continue
		}

		_, _ = e.Session.Cache().CreateEntityProperty(entity, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fqdn.Name,
			Entity:  entity,
			Session: e.Session,
		})
	}
}

func ProcessEmailsWithSource(e *et.Event, entities []*dbt.Entity, src *et.Source) {
	for _, entity := range entities {
		email, ok := entity.Asset.(*general.Identifier)
		if !ok || email == nil || email.Type != general.EmailAddress || email.EntityID == "" {
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

		_, _ = e.Session.Cache().CreateEntityProperty(entity, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    email.UniqueID,
			Meta:    meta,
			Entity:  entity,
			Session: e.Session,
		})
	}
}
