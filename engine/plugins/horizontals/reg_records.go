// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"fmt"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type horRegRec struct {
	name   string
	plugin *horizPlugin
}

func (h *horRegRec) Name() string {
	return h.name
}

func (h *horRegRec) check(e *et.Event) error {
	var rlabel string
	t := e.Entity.Asset.AssetType()

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	switch t {
	case oam.AutnumRecord:
		rlabel = "registrant"
	case oam.DomainRecord:
		rlabel = "registrant_contact"
	case oam.IPNetRecord:
		rlabel = "registrant"
	default:
		return fmt.Errorf("asset type not supported: %s", t)
	}

	cr, err := h.plugin.getContactRecord(e.Session, e.Entity, rlabel)
	if err != nil {
		return nil
	}

	orgs, locs := h.plugin.lookupContactRecordOrgsAndLocations(e.Session, cr)
	if len(orgs) == 0 && len(locs) == 0 {
		return nil
	}

	switch t {
	case oam.AutnumRecord:
		h.processAutnumRecord(e, orgs, locs)
	case oam.DomainRecord:
		h.processDomainRecord(e, orgs, locs)
	case oam.IPNetRecord:
		h.processIPNetRecord(e, orgs, locs)
	}
	return nil
}

func (h *horRegRec) processAutnumRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the autnum record / registered autonomous system is in scope
	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		for _, o := range orgs {
			h.plugin.enqueueIfOutOfScope(e.Session, o)
		}
		for _, loc := range locs {
			h.plugin.enqueueIfOutOfScope(e.Session, loc)
		}
		return
	}

	var found bool
	for _, o := range orgs {
		if h.plugin.isEntityInScope(e.Session, o) {
			found = true
			break
		}
	}

	if !found {
		for _, loc := range locs {
			if h.plugin.isEntityInScope(e.Session, loc) {
				found = true
				break
			}
		}
	}

	if found {
		// the autonomous system should be added to the scope
		if an, valid := e.Entity.Asset.(*oamreg.AutnumRecord); valid {
			if !h.plugin.isEntityInScope(e.Session, e.Entity) {
				if as := h.plugin.addASNetblocksToScope(e.Session, an.Number); as != nil {
					h.plugin.addToScopeAndEnqueue(e.Session, as)
				}
			}
		}
		for _, o := range orgs {
			h.plugin.enqueueIfOutOfScope(e.Session, o)
		}
		for _, loc := range locs {
			h.plugin.enqueueIfOutOfScope(e.Session, loc)
		}
	}
}

func (h *horRegRec) processDomainRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the domain record / registered domain name is in scope
	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		for _, o := range orgs {
			h.plugin.enqueueIfOutOfScope(e.Session, o)
		}
		for _, loc := range locs {
			h.plugin.enqueueIfOutOfScope(e.Session, loc)
		}
		return
	}

	var found bool
	for _, o := range orgs {
		if h.plugin.isEntityInScope(e.Session, o) {
			found = true
			break
		}
	}

	if !found {
		for _, loc := range locs {
			if h.plugin.isEntityInScope(e.Session, loc) {
				found = true
				break
			}
		}
	}

	if found {
		// get the registered domain FQDN entity
		if fqdn, err := h.plugin.getRegisteredDomainEntity(e.Session, e.Entity); err == nil && fqdn != nil {
			// add the FQDN to the session scope and review it
			h.plugin.enqueueIfOutOfScope(e.Session, e.Entity)
		}
		for _, o := range orgs {
			h.plugin.enqueueIfOutOfScope(e.Session, o)
		}
		for _, loc := range locs {
			h.plugin.enqueueIfOutOfScope(e.Session, loc)
		}
	}
}

func (h *horRegRec) processIPNetRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the ipnet record / registered netblock is in scope
	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		for _, o := range orgs {
			h.plugin.enqueueIfOutOfScope(e.Session, o)
		}
		for _, loc := range locs {
			h.plugin.enqueueIfOutOfScope(e.Session, loc)
		}
		return
	}

	var found bool
	for _, o := range orgs {
		if h.plugin.isEntityInScope(e.Session, o) {
			found = true
			break
		}
	}

	if !found {
		for _, loc := range locs {
			if h.plugin.isEntityInScope(e.Session, loc) {
				found = true
				break
			}
		}
	}

	if found {
		// get the registered CIDR Netblock entity
		if nb, err := h.plugin.getRegisteredNetblockEntity(e.Session, e.Entity); err == nil && nb != nil {
			// the netblock should be added to the scope
			h.plugin.enqueueIfOutOfScope(e.Session, nb)
		}
		for _, o := range orgs {
			h.plugin.enqueueIfOutOfScope(e.Session, o)
		}
		for _, loc := range locs {
			h.plugin.enqueueIfOutOfScope(e.Session, loc)
		}
	}
}
