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

		orgs, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization")
		if err != nil {
			continue
		}

		for _, oe := range orgs {
			if seen.Has(oe.ToEntity.ID) {
				continue
			}

			a, err := sess.DB().FindEntityById(ctx, oe.ToEntity.ID)
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
