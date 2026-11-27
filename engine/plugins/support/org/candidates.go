// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"time"

	"github.com/caffix/stringset"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// OrgsSharingName returns the organizations recorded under one of the given
// names (an organization's common or legal name), found through the name
// identifiers the graph de-duplicates on. A shared name is a weak signal on
// its own — companies in different jurisdictions reuse names — so these
// candidates are scored, never merged on the name alone. Read-only.
func OrgsSharingName(sess et.Session, names []string) []*dbt.Entity {
	orgents, err := orgsWithSameNames(sess, names)
	if err != nil {
		return nil
	}

	return orgents
}

// OrgsSharingIdentifier returns the other organizations that hold one of the
// same registered identifiers as orgent (the same LEI, company number, SEC
// CIK, and so on). Identifiers are de-duplicated in the graph by value and
// type, so organizations that share one point at the same Identifier entity;
// this walks orgent's "id" edges to those shared entities and back along their
// incoming "id" edges to the other organizations. A shared identifier is the
// strongest duplicate signal, so these candidates are worth scoring. The walk
// is read-only and bounded by how many identifiers orgent holds; orgent itself
// is never returned.
func OrgsSharingIdentifier(sess et.Session, orgent *dbt.Entity) []*dbt.Entity {
	if orgent == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	seen := stringset.New()
	defer seen.Close()
	seen.Insert(orgent.ID)

	var out []*dbt.Entity
	ids, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "id")
	if err != nil {
		return nil
	}

	for _, ide := range ids {
		ident, err := sess.DB().FindEntityById(ctx, ide.ToEntity.ID)
		if err != nil || ident == nil {
			continue
		}

		// other assets reach the identifier by "id"; keep only organizations
		holders, err := sess.DB().IncomingEdges(ctx, ident, time.Time{}, "id")
		if err != nil {
			continue
		}

		for _, he := range holders {
			if seen.Has(he.FromEntity.ID) {
				continue
			}

			a, err := sess.DB().FindEntityById(ctx, he.FromEntity.ID)
			if err != nil || a == nil {
				continue
			}
			if _, ok := a.Asset.(*oamorg.Organization); ok {
				seen.Insert(a.ID)
				out = append(out, a)
			}
		}
	}

	return out
}

// OrgsSharingPhone returns the other organizations that share a phone number
// with orgent, reached through contact records
// (Organization ← ContactRecord --phone--> Phone and back). A shared phone is
// a weaker signal than a shared identifier — switchboards and answering
// services are reused — so these candidates warrant a proposal for review
// rather than an automatic merge. The walk is read-only; orgent is never
// returned.
func OrgsSharingPhone(sess et.Session, orgent *dbt.Entity) []*dbt.Entity {
	if orgent == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	seen := stringset.New()
	defer seen.Close()
	seen.Insert(orgent.ID)

	var out []*dbt.Entity
	crs, err := sess.DB().IncomingEdges(ctx, orgent, time.Time{}, "organization")
	if err != nil {
		return nil
	}

	for _, cre := range crs {
		cr, err := sess.DB().FindEntityById(ctx, cre.FromEntity.ID)
		if err != nil || cr == nil {
			continue
		}
		if _, ok := cr.Asset.(*oamcon.ContactRecord); !ok {
			continue
		}

		phones, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "phone")
		if err != nil {
			continue
		}

		for _, phe := range phones {
			ph, err := sess.DB().FindEntityById(ctx, phe.ToEntity.ID)
			if err != nil || ph == nil {
				continue
			}

			out = append(out, orgsOnPhone(ctx, sess, ph, seen)...)
		}
	}

	return out
}

// orgsOnPhone returns the organizations whose contact records carry the phone
// entity ph, skipping any already in seen. Read-only.
func orgsOnPhone(ctx context.Context, sess et.Session, ph *dbt.Entity, seen *stringset.Set) []*dbt.Entity {
	var out []*dbt.Entity

	crs, err := sess.DB().IncomingEdges(ctx, ph, time.Time{}, "phone")
	if err != nil {
		return nil
	}

	for _, cre := range crs {
		cr, err := sess.DB().FindEntityById(ctx, cre.FromEntity.ID)
		if err != nil || cr == nil {
			continue
		}
		if _, ok := cr.Asset.(*oamcon.ContactRecord); !ok {
			continue
		}

		out = append(out, orgsOnContactRecord(ctx, sess, cr, seen)...)
	}

	return out
}

// OrgsSharingAddress returns the other organizations that share a street
// address with orgent, reached through its locations and contact records
// (Organization → legal_address/hq_address/location → StreetAddress and back, and
// via a ContactRecord at the same location). A shared address is a supporting
// signal — shared buildings and registered-agent addresses are reused by many
// companies — so these candidates are scored, never merged on the address
// alone. The walk is read-only; orgent is never returned.
func OrgsSharingAddress(sess et.Session, orgent *dbt.Entity) []*dbt.Entity {
	if orgent == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	var locs []*dbt.Entity
	if edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "legal_address", "hq_address",
		"street_address"); err == nil {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamcon.StreetAddress); ok {
					locs = append(locs, a)
				}
			}
		}
	}

	// expand to the stored locations that match these ones
	locs = append(locs, matchingStreetAddresses(sess, locs)...)

	seen := stringset.New()
	defer seen.Close()
	seen.Insert(orgent.ID)

	var out []*dbt.Entity
	for _, loc := range locs {
		edges, err := sess.DB().IncomingEdges(ctx, loc, time.Time{}, "legal_address", "hq_address", "street_address")
		if err != nil {
			continue
		}

		for _, edge := range edges {
			a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID)
			if err != nil || a == nil {
				continue
			}

			switch a.Asset.(type) {
			case *oamorg.Organization:
				if !seen.Has(a.ID) {
					seen.Insert(a.ID)
					out = append(out, a)
				}
			case *oamcon.ContactRecord:
				out = append(out, orgsOnContactRecord(ctx, sess, a, seen)...)
			}
		}
	}

	return out
}

// orgsOnContactRecord returns the organizations a contact record names through
// its "organization" edges, skipping any already in seen. Read-only.
func orgsOnContactRecord(ctx context.Context, sess et.Session, cr *dbt.Entity, seen *stringset.Set) []*dbt.Entity {
	var out []*dbt.Entity

	edges, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization")
	if err != nil {
		return nil
	}

	for _, edge := range edges {
		if seen.Has(edge.ToEntity.ID) {
			continue
		}

		a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil || a == nil {
			continue
		}
		if _, ok := a.Asset.(*oamorg.Organization); ok {
			seen.Insert(a.ID)
			out = append(out, a)
		}
	}

	return out
}
