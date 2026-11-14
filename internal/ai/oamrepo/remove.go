// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/owasp-amass/amass/v5/internal/ai/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

var _ review.OrganizationRemover = Adapter{}

// RemoveOrganization deletes an organization with its relationships and
// properties, and returns what it removed so RestoreOrganization can put
// it back.
func (a Adapter) RemoveOrganization(ctx context.Context, id string) (review.OrganizationRemoval, error) {
	rec := review.OrganizationRemoval{OrganizationID: id}
	if a.Repo == nil {
		return rec, errors.New("missing OAM repository")
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	ent, err := a.entityOfType(wctx, id, string(oam.Organization))
	if err != nil {
		return rec, err
	}
	if rec.Asset, err = ent.Asset.JSON(); err != nil {
		return rec, err
	}

	tags, err := a.tagsOf(wctx, ent)
	if err != nil {
		return rec, err
	}
	for _, t := range tags {
		if t == nil || t.Property == nil {
			continue
		}
		mt, err := mergedTag(t.Property)
		if err != nil {
			return rec, err
		}
		rec.Tags = append(rec.Tags, mt)
	}

	for _, outgoing := range []bool{true, false} {
		edges, err := a.edgesOf(wctx, ent, outgoing)
		if err != nil {
			return rec, err
		}
		for _, edge := range edges {
			m, err := a.recordEdge(wctx, edge, outgoing)
			if err != nil {
				return rec, err
			}
			rec.Edges = append(rec.Edges, m)
		}
	}

	if err := a.Repo.DeleteEntity(wctx, ent.ID); err != nil {
		return rec, fmt.Errorf("delete organization %s: %w", ent.ID, err)
	}

	return rec, nil
}

// recordEdge records a relationship of an entity about to be removed.
func (a Adapter) recordEdge(ctx context.Context, edge *dbt.Edge, outgoing bool) (review.MergedEdge, error) {
	m := review.MergedEdge{ID: edge.ID, Outgoing: outgoing}
	if edge.Relation == nil || edge.FromEntity == nil || edge.ToEntity == nil {
		return m, fmt.Errorf("edge %s is incomplete", edge.ID)
	}

	other := edge.ToEntity
	if !outgoing {
		other = edge.FromEntity
	}

	var err error
	m.OtherID, m.Label, m.RelationType = other.ID, edge.Relation.Label(), string(edge.Relation.RelationType())
	if m.Relation, err = edge.Relation.JSON(); err != nil {
		return m, err
	}

	tags, err := a.edgeTagsOf(ctx, edge)
	if err != nil {
		return m, err
	}
	for _, t := range tags {
		if t == nil || t.Property == nil {
			continue
		}
		mt, err := mergedTag(t.Property)
		if err != nil {
			return m, err
		}
		m.Tags = append(m.Tags, mt)
	}

	return m, nil
}

// RestoreOrganization recreates a removed organization with its properties
// and its relationships to the entities that still exist, and returns its
// new ID.
func (a Adapter) RestoreOrganization(ctx context.Context, rec review.OrganizationRemoval) (string, error) {
	if a.Repo == nil {
		return "", errors.New("missing OAM repository")
	}

	var o oamorg.Organization
	if err := json.Unmarshal(rec.Asset, &o); err != nil {
		return "", fmt.Errorf("removal record organization: %w", err)
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	ent, err := a.Repo.CreateAsset(wctx, &o)
	if err != nil {
		return "", err
	} else if ent == nil {
		return "", errors.New("failed to restore the organization")
	}

	for _, t := range rec.Tags {
		p, err := propertyFromTag(t)
		if err != nil {
			return ent.ID, err
		}
		if _, err := a.Repo.CreateEntityProperty(wctx, ent, p); err != nil {
			return ent.ID, err
		}
	}

	for _, m := range rec.Edges {
		other, err := a.Repo.FindEntityById(wctx, m.OtherID)
		if err != nil || other == nil {
			// The other end was deleted since the removal.
			continue
		}

		rel, err := relationFromJSON(m.RelationType, m.Relation)
		if err != nil {
			return ent.ID, err
		}

		from, to := ent, other
		if !m.Outgoing {
			from, to = other, ent
		}
		edge, err := a.createEdge(wctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
		if err != nil {
			return ent.ID, err
		}
		for _, t := range m.Tags {
			p, err := propertyFromTag(t)
			if err != nil {
				return ent.ID, err
			}
			if _, err := a.Repo.CreateEdgeProperty(wctx, edge, p); err != nil {
				return ent.ID, err
			}
		}
	}

	return ent.ID, nil
}
