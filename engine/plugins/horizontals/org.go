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
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type horOrg struct {
	name   string
	plugin *horizPlugin
}

func (h *horOrg) Name() string {
	return h.name
}

func (h *horOrg) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to cast the Organization asset")
	}

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	// A privacy-proxy / registrar-proxy organization is the registrant of
	// record for thousands of unrelated domains; never expand scope from it
	// (principle 8, horizontal-domain-correlation-spec.md).
	if h.plugin.isPrivacyProxyOrg(e.Entity) {
		return nil
	}

	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		h.processInScope(e)
	} else {
		h.processOutOfScope(e)
	}
	return nil
}

func (h *horOrg) processInScope(e *et.Event) {
	// Scored horizontal expansion for this in-scope organization: the registered
	// domains, netblocks and autonomous systems its signals tie to it are scored
	// and the strong ones added to scope, journaled and reconsiderable, in place
	// of the old single-signal enqueues.
	h.plugin.expandRelatedDomains(e, e.Entity)
	h.plugin.expandRelatedInfrastructure(e, e.Entity)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.ContactRecord), h.plugin.name)
	if err != nil {
		return
	}

	edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since, "organization")
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
		// Bring the contact record's other organizations and locations into
		// scope; their own events drive the scored expansion for each. The
		// netblocks and ASes are handled by expandRelatedInfrastructure above.
		if orgs, locs := h.plugin.lookupContactRecordOrgsAndLocations(e.Session, from); len(orgs) > 0 || len(locs) > 0 {
			for _, o := range orgs {
				h.plugin.enqueueIfOutOfScope(e.Session, o)
			}
			for _, loc := range locs {
				h.plugin.enqueueIfOutOfScope(e.Session, loc)
			}
		}
	}
}

func (h *horOrg) processOutOfScope(e *et.Event) {
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
