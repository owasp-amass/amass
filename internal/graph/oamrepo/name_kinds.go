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
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeople "github.com/owasp-amass/open-asset-model/people"
)

// ApplyNameKind writes a name proposal decided as kind: a Person from the
// name, or the Organization stored under its normalized name (a new one when
// none is), linked from the record with the amass-ai source and confidence.
// A record names an organization by "organization" when it is a contact
// record, and by the proposal's label otherwise. The raw name kept on the
// record is removed.
func (a Adapter) ApplyNameKind(ctx context.Context, p review.NameKindProposal, kind string,
	confidence int) (review.NameKindOutcome, error) {
	var o review.NameKindOutcome
	if a.Repo == nil {
		return o, errors.New("missing OAM repository")
	}
	rec, err := a.Repo.FindEntityById(ctx, p.RecordID)
	if err != nil || rec == nil || rec.Asset == nil {
		return o, fmt.Errorf("record %s is no longer stored", p.RecordID)
	}

	label := p.Label
	var asset oam.Asset
	var existing []*dbt.Entity
	switch kind {
	case review.NameKindPerson:
		name, ok := semantics.ParsePersonName(p.Name)
		if !ok {
			return o, fmt.Errorf("%q does not read as a person's name", p.Name)
		}
		asset = &oampeople.Person{ID: name.Full, FullName: name.Full, FirstName: name.First,
			MiddleName: name.Middle, FamilyName: name.Last}
		existing, _ = a.Repo.FindEntitiesByContent(ctx, oam.Person, time.Time{}, 1,
			dbt.ContentFilters{"unique_id": name.Full})
	case review.NameKindOrganization:
		key := semantics.OrgNameKey(p.Name)
		if key == "" {
			return o, fmt.Errorf("%q has no organization name", p.Name)
		}
		if rec.Asset.AssetType() == oam.ContactRecord {
			label = "organization"
		}
		asset = &oamorg.Organization{ID: key + ":" + uuid.New().String(), Name: key}
		existing, _ = a.Repo.FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 1,
			dbt.ContentFilters{"name": key})
	default:
		return o, fmt.Errorf("a name is decided as %s or %s, not %q", review.NameKindPerson,
			review.NameKindOrganization, kind)
	}

	ent := firstEntity(existing)
	if ent == nil {
		if ent, err = a.Repo.CreateAsset(ctx, asset); err != nil {
			return o, err
		}
		o.Created = true
	}
	o.EntityID = ent.ID

	if o.EdgeID, _, err = a.ApplyOwnership(ctx, lens.ProposedEdge{FromID: rec.ID,
		FromType: string(rec.Asset.AssetType()), Label: label, RelationType: string(oam.SimpleRelation),
		ToID: ent.ID, ToType: string(ent.Asset.AssetType())}, confidence); err != nil {
		if o.Created {
			_ = a.Repo.DeleteEntity(ctx, ent.ID)
		}
		return review.NameKindOutcome{}, err
	}

	tags, _ := a.Repo.FindEntityTags(ctx, rec, time.Time{}, graph.UncertainNameProp)
	for _, t := range tags {
		if t != nil && t.Property != nil && t.Property.Value() == p.Name {
			_ = a.Repo.DeleteEntityTag(ctx, t.ID)
		}
	}
	return o, nil
}

func firstEntity(ents []*dbt.Entity) *dbt.Entity {
	for _, e := range ents {
		if e != nil && e.Asset != nil {
			return e
		}
	}
	return nil
}

// RetractNameKind undoes an applied name proposal: its relationship is
// removed, the Person or Organization too when the decision created it and
// nothing else relates to it, and the raw name is kept on its record again.
func (a Adapter) RetractNameKind(ctx context.Context, p review.NameKindProposal, o review.NameKindOutcome) error {
	if a.Repo == nil {
		return errors.New("missing OAM repository")
	}
	if o.EdgeID != "" {
		if err := a.Repo.DeleteEdge(ctx, o.EdgeID); err != nil && !missing(err) {
			return err
		}
	}
	if ent, err := a.Repo.FindEntityById(ctx, o.EntityID); o.Created && err == nil && ent != nil {
		in, ierr := a.Repo.IncomingEdges(ctx, ent, time.Time{})
		out, oerr := a.Repo.OutgoingEdges(ctx, ent, time.Time{})
		if len(in) == 0 && len(out) == 0 && (ierr == nil || emptyEdgeLookup(ierr)) &&
			(oerr == nil || emptyEdgeLookup(oerr)) {
			if err := a.Repo.DeleteEntity(ctx, ent.ID); err != nil {
				return err
			}
		}
	}

	rec, err := a.Repo.FindEntityById(ctx, p.RecordID)
	if err != nil || rec == nil {
		return nil
	}
	_, err = a.Repo.CreateEntityProperty(ctx, rec,
		&general.SimpleProperty{PropertyName: graph.UncertainNameProp, PropertyValue: p.Name})
	return err
}
