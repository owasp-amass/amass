// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"

	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
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

		if len(impacted) > 0 {
			h.plugin.process(e, impacted)
			h.plugin.addAssociatedRelationship(e, assocs)
		}
	}
	return nil
}

func (h *horContact) lookup(e *et.Event, entity *dbt.Entity, conf int) []*scope.Association {
	labels := []string{"organization", "location", "id"}

	var results []*scope.Association
	if edges, err := e.Session.Cache().OutgoingEdges(entity,
		e.Session.Cache().StartTime(), labels...); err == nil && len(edges) > 0 {
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
