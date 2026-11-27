// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

var _ review.PersonConverter = Adapter{}

// ConvertPersonToOrganization converts a Person stored under an
// organization's name. The Organization is the one a contact record naming
// the person already names under that name (p.OrgID), or a new one. The
// Person is removed with a record of everything it had, and each of its
// relationships is recreated on the Organization: a contact record's person
// becomes its organization, a label valid for an Organization is kept, and
// any other is left in the record (Dropped), to come back with the Person.
func (a Adapter) ConvertPersonToOrganization(ctx context.Context,
	p lens.OrgNamedPerson) (review.PersonConversion, error) {
	var rec review.PersonConversion
	if a.Repo == nil {
		return rec, errors.New("missing OAM repository")
	}
	key := semantics.OrgNameKey(p.Person)
	if key == "" {
		return rec, fmt.Errorf("%q has no organization name", p.Person)
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	if _, err := a.entityOfType(wctx, p.PersonID, string(oam.Person)); err != nil {
		return rec, err
	}
	var org *dbt.Entity
	if p.OrgID != "" {
		if ent, err := a.entityOfType(wctx, p.OrgID, string(oam.Organization)); err == nil &&
			semantics.OrgNameKey(graphOrgName(ent)) == key {
			org = ent
		}
	}
	if org == nil {
		ent, err := a.Repo.CreateAsset(wctx, &oamorg.Organization{ID: key + ":" + uuid.New().String(), Name: key})
		if err != nil {
			return rec, err
		} else if ent == nil {
			return rec, errors.New("failed to create the organization")
		}
		org, rec.OrgCreated = ent, true
	}
	rec.OrgID = org.ID

	removal, err := a.RemoveEntity(wctx, p.PersonID)
	if err != nil {
		if rec.OrgCreated {
			_ = a.Repo.DeleteEntity(wctx, org.ID)
		}
		return review.PersonConversion{}, err
	}
	rec.Person = removal

	if err := a.moveToOrganization(wctx, org, &rec); err != nil {
		if _, rerr := a.RevertPersonConversion(ctx, rec); rerr != nil {
			return rec, fmt.Errorf("%w; undoing it failed too: %v", err, rerr)
		}
		return review.PersonConversion{}, err
	}
	return rec, nil
}

// moveToOrganization recreates the removed Person's relationships, and for a
// created Organization its properties, on org.
func (a Adapter) moveToOrganization(ctx context.Context, org *dbt.Entity, rec *review.PersonConversion) error {
	if rec.OrgCreated {
		for _, t := range rec.Person.Tags {
			prop, err := propertyFromTag(t)
			if err != nil {
				return err
			}
			if _, err := a.Repo.CreateEntityProperty(ctx, org, prop); err != nil {
				return err
			}
		}
	}

	for _, m := range rec.Person.Edges {
		other, err := a.Repo.FindEntityById(ctx, m.OtherID)
		if err != nil || other == nil || other.Asset == nil {
			// the other end is gone; restoring the Person skips it too
			continue
		}

		label := m.Label
		if !m.Outgoing && other.Asset.AssetType() == oam.ContactRecord && label == "person" {
			label = "organization"
		}
		from, to := oam.Organization, other.Asset.AssetType()
		if !m.Outgoing {
			from, to = to, from
		}
		rel, err := relationFromJSON(m.RelationType, m.Relation)
		if err != nil {
			return err
		}
		if label != m.Label {
			sr, ok := rel.(*general.SimpleRelation)
			if !ok {
				rec.Dropped = append(rec.Dropped, m)
				continue
			}
			sr.Name = label
		}
		if !oam.ValidRelationship(from, label, rel.RelationType(), to) {
			rec.Dropped = append(rec.Dropped, m)
			continue
		}

		edge, existed, err := a.survivorEdge(ctx, org, other, rel, m.Outgoing)
		if err != nil {
			return err
		}
		if existed {
			continue
		}
		rec.AddedEdges = append(rec.AddedEdges, edge.ID)
		for _, t := range m.Tags {
			prop, err := propertyFromTag(t)
			if err != nil {
				return err
			}
			if _, err := a.Repo.CreateEdgeProperty(ctx, edge, prop); err != nil {
				return err
			}
		}
	}
	return nil
}

// RevertPersonConversion undoes a conversion: the relationships it created
// are removed, the Organization too when the conversion created it and
// nothing else relates to it, and the Person is restored with everything it
// had. It returns the restored Person's ID.
func (a Adapter) RevertPersonConversion(ctx context.Context, rec review.PersonConversion) (string, error) {
	if a.Repo == nil {
		return "", errors.New("missing OAM repository")
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	for _, id := range rec.AddedEdges {
		if err := a.Repo.DeleteEdge(wctx, id); err != nil && !missing(err) {
			return "", err
		}
	}
	if rec.OrgCreated {
		if org, err := a.Repo.FindEntityById(wctx, rec.OrgID); err == nil && org != nil {
			in, ierr := a.Repo.IncomingEdges(wctx, org, time.Time{})
			out, oerr := a.Repo.OutgoingEdges(wctx, org, time.Time{})
			if len(in) == 0 && len(out) == 0 && (ierr == nil || emptyEdgeLookup(ierr)) &&
				(oerr == nil || emptyEdgeLookup(oerr)) {
				if err := a.Repo.DeleteEntity(wctx, org.ID); err != nil {
					return "", err
				}
			}
		}
	}
	return a.RestoreEntity(wctx, rec.Person)
}

// graphOrgName is a stored Organization's name.
func graphOrgName(ent *dbt.Entity) string {
	if o, ok := ent.Asset.(*oamorg.Organization); ok {
		return o.Name
	}
	return ""
}
