// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeople "github.com/owasp-amass/open-asset-model/people"
)

var _ review.EntityRemover = Adapter{}

// RemoveEntity deletes an Organization or a Person with its relationships
// and properties, and returns what it removed so RestoreEntity can put it
// back.
func (a Adapter) RemoveEntity(ctx context.Context, id string) (review.EntityRemoval, error) {
	rec := review.EntityRemoval{EntityID: id}
	if a.Repo == nil {
		return rec, errors.New("missing OAM repository")
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	ent, err := a.Repo.FindEntityById(wctx, id)
	if err != nil {
		return rec, err
	}
	if ent == nil || ent.Asset == nil {
		return rec, fmt.Errorf("entity %s is not stored", id)
	}
	switch t := ent.Asset.AssetType(); t {
	case oam.Organization:
	case oam.Person:
		rec.AssetType = string(t)
	default:
		return rec, fmt.Errorf("entity %s is a %s, not an Organization or a Person", id, t)
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
		return rec, fmt.Errorf("delete %s %s: %w", ent.Asset.AssetType(), ent.ID, err)
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

// RestoreEntity recreates a removed entity with its properties and its
// relationships to the entities that still exist, and returns its new ID.
func (a Adapter) RestoreEntity(ctx context.Context, rec review.EntityRemoval) (string, error) {
	if a.Repo == nil {
		return "", errors.New("missing OAM repository")
	}

	var asset oam.Asset
	switch rec.AssetType {
	case "", string(oam.Organization):
		asset = &oamorg.Organization{}
	case string(oam.Person):
		asset = &oampeople.Person{}
	default:
		return "", fmt.Errorf("a removed %s cannot be restored", rec.AssetType)
	}
	if err := json.Unmarshal(rec.Asset, asset); err != nil {
		return "", fmt.Errorf("removal record asset: %w", err)
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	ent, err := a.Repo.CreateAsset(wctx, asset)
	if err != nil {
		return "", err
	} else if ent == nil {
		return "", errors.New("failed to restore the removed entity")
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
