// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"

	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/property"
)

type horContact struct {
	name   string
	plugin *horizPlugin
}

func (h *horContact) Name() string {
	return h.name
}

func (h *horContact) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*contact.ContactRecord)
	if !ok {
		return errors.New("failed to extract the ContactRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.ContactRecord), string(oam.ContactRecord), h.plugin.name)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	conf := matches.Confidence(h.plugin.name)
	if conf == -1 {
		conf = matches.Confidence(string(oam.ContactRecord))
	}

	if assocs := h.lookup(e, e.Entity, conf); len(assocs) > 0 {
		var impacted []*dbt.Entity

		for _, assoc := range assocs {
			if assoc.ScopeChange {
				h.plugin.log.Info(assoc.Rationale)
				impacted = append(impacted, assoc.ImpactedAssets...)
			}
		}

		src := h.plugin.source
		var assets []*dbt.Entity
		for _, im := range impacted {
			if a, err := e.Session.Cache().FindEntityByContent(im.Asset, e.Session.Cache().StartTime()); err == nil && len(a) == 1 {
				assets = append(assets, a[0])
			} else if n := h.store(e, im.Asset, src); n != nil {
				assets = append(assets, n)
			}
		}

		if len(assets) > 0 {
			h.plugin.process(e, assets, src)
			h.plugin.addAssociatedRelationship(e, assocs)
		}
	}
	return nil
}

func (h *horContact) lookup(e *et.Event, asset *dbt.Entity, conf int) []*scope.Association {
	labels := []string{"organization", "location", "email"}

	var results []*scope.Association
	if edges, err := e.Session.Cache().OutgoingEdges(asset, e.Session.Cache().StartTime(), labels...); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			entity, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
			if err != nil {
				continue
			}
			// check if these asset discoveries could change the scope
			if assocs, err := e.Session.Scope().IsAssociated(e.Session.Cache(), &scope.Association{
				Submission:  entity,
				Confidence:  conf,
				ScopeChange: true,
			}); err == nil && len(assocs) > 0 {
				results = append(results, assocs...)
			}
		}
	}
	return results
}

func (h *horContact) store(e *et.Event, asset oam.Asset, src *et.Source) *dbt.Entity {
	a, err := e.Session.Cache().CreateAsset(asset)
	if err != nil || a == nil {
		return nil
	}

	_, _ = e.Session.Cache().CreateEntityProperty(a, &property.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return a
}
