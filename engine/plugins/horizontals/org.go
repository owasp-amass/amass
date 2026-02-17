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
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
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

	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		h.processInScope(e)
	} else {
		h.processOutOfScope(e)
	}
	return nil
}

func (h *horOrg) processInScope(e *et.Event) {
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
		// add the contact record orgs and locations to the scope
		if orgs, locs := h.plugin.lookupContactRecordOrgsAndLocations(e.Session, from); len(orgs) > 0 || len(locs) > 0 {
			for _, o := range orgs {
				h.plugin.enqueueIfOutOfScope(e.Session, o)
			}
			for _, loc := range locs {
				h.plugin.enqueueIfOutOfScope(e.Session, loc)
			}
		}
		// if the contact record belongs to a registration record or TLS certificate, add to the scope
		if edges, err := e.Session.DB().IncomingEdges(ctx, from, since); err == nil {
			for _, edge := range edges {
				if from, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil {
					switch v := from.Asset.(type) {
					case *oamreg.AutnumRecord:
						if !h.plugin.isEntityInScope(e.Session, from) {
							if as := h.plugin.addASNetblocksToScope(e.Session, v.Number); as != nil {
								h.plugin.addToScopeAndEnqueue(e.Session, as)
							}
						}
					case *oamreg.DomainRecord:
						if fqdn, err := h.plugin.getRegisteredDomainEntity(e.Session, from); err == nil && fqdn != nil {
							h.plugin.enqueueIfOutOfScope(e.Session, fqdn)
						}
					case *oamreg.IPNetRecord:
						if nb, err := h.plugin.getRegisteredNetblockEntity(e.Session, from); err == nil && nb != nil {
							h.plugin.enqueueIfOutOfScope(e.Session, nb)
						}
					case *oamcert.TLSCertificate:
						h.plugin.enqueueIfOutOfScope(e.Session, from)
					}
				}
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
