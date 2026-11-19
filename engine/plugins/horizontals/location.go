// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
)

type horLocation struct {
	name   string
	plugin *horizPlugin
}

func (h *horLocation) Name() string {
	return h.name
}

func (h *horLocation) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamcon.Location)
	if !ok {
		return errors.New("failed to cast the Location asset")
	}

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		h.processInScope(e)
	} else {
		h.processOutOfScope(e)
	}
	return nil
}

func (h *horLocation) processInScope(e *et.Event) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Location), string(oam.ContactRecord), h.plugin.name)
	if err != nil {
		return
	}

	// get all the contact records that use this location
	edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since, "location")
	if err != nil || len(edges) == 0 {
		return
	}

	for _, edge := range edges {
		from, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil {
			continue
		}
		// check this is a contact record
		if from.Asset.AssetType() != oam.ContactRecord {
			continue
		}
		// Run the scored horizontal domain and infrastructure expansion for each
		// organization at this location, and bring the organizations and
		// locations into scope (replacing the old single-signal enqueues).
		if orgs, locs := h.plugin.lookupContactRecordOrgsAndLocations(e.Session, from); len(orgs) > 0 || len(locs) > 0 {
			for _, o := range orgs {
				h.plugin.expandRelatedDomains(e, o)
				h.plugin.expandRelatedInfrastructure(e, o)
				h.plugin.enqueueIfOutOfScope(e.Session, o)
			}
			for _, loc := range locs {
				h.plugin.enqueueIfOutOfScope(e.Session, loc)
			}
		}
	}
}

func (h *horLocation) processOutOfScope(e *et.Event) {
	assocs, err := e.Session.Scope().IsAssociated(&et.Association{
		Submission:  e.Entity,
		ScopeChange: true,
	})
	if err != nil {
		return
	}

	for _, assoc := range assocs {
		if assoc.ScopeChange {
			e.Session.Log().Info(assoc.Rationale)
		}
	}
}
