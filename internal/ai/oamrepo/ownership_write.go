// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
)

// ApplyOwnership writes an approved ownership proposal as one OAM
// relationship, tagged with the amass-ai source and confidence the same way
// the engine's plugins record theirs. Both entities must still exist with the
// proposed types, and the relationship must be one OAM defines. When the
// relationship is already stored, its ID is returned and nothing is written.
func (a Adapter) ApplyOwnership(ctx context.Context, e ai.ProposedEdge, confidence int) (string, bool, error) {
	if a.Repo == nil {
		return "", false, errors.New("missing OAM repository")
	}
	if e.RelationType != string(oam.SimpleRelation) {
		return "", false, fmt.Errorf("only %s relationships are written, not %s", oam.SimpleRelation, e.RelationType)
	}
	if confidence < 0 || confidence > 100 {
		return "", false, fmt.Errorf("confidence %d is outside 0..100", confidence)
	}

	from, err := a.entityOfType(ctx, e.FromID, e.FromType)
	if err != nil {
		return "", false, err
	}

	to, err := a.entityOfType(ctx, e.ToID, e.ToType)
	if err != nil {
		return "", false, err
	}
	if !AllowedRelation(e.FromType, e.Label, e.ToType) {
		return "", false, fmt.Errorf("OAM does not define %s --%s--> %s", e.FromType, e.Label, e.ToType)
	}

	existing, err := a.Repo.OutgoingEdges(ctx, from, time.Time{}, e.Label)
	if err != nil && !emptyEdgeLookup(err) {
		return "", false, err
	}
	for _, edge := range existing {
		if edge != nil && edge.ToEntity != nil && edge.ToEntity.ID == to.ID && edge.Relation != nil &&
			edge.Relation.Label() == e.Label {
			return edge.ID, true, nil
		}
	}

	// The edge and its source are written together even if the caller's
	// context ends between them, so no amass-ai edge is left unsourced.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	edge, err := a.Repo.CreateEdge(wctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: e.Label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil {
		return "", false, err
	} else if edge == nil {
		return "", false, errors.New("failed to create the edge")
	}

	if _, err := a.Repo.CreateEdgeProperty(wctx, edge, &general.SourceProperty{
		Source:     ai.InferenceSource,
		Confidence: confidence,
	}); err != nil {
		return edge.ID, false, err
	}

	return edge.ID, false, nil
}

// emptyEdgeLookup reports whether err is a repository's way of saying an
// entity has no edges: every asset-db backend returns an error for that.
func emptyEdgeLookup(err error) bool {
	return err != nil && strings.HasPrefix(strings.TrimSpace(err.Error()), "zero edges found")
}

// entityOfType finds the entity id and checks it is still of type t.
func (a Adapter) entityOfType(ctx context.Context, id, t string) (*dbt.Entity, error) {
	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("entity %s: %w", id, err)
	}
	if ent == nil || ent.Asset == nil {
		return nil, fmt.Errorf("entity %s has no asset", id)
	}
	if got := string(ent.Asset.AssetType()); got != t {
		return nil, fmt.Errorf("entity %s is now %s, not %s", id, got, t)
	}

	return ent, nil
}

// RetractOwnership removes the amass-ai source from edge id and deletes the
// edge when no other source records it. It reports whether the edge was
// deleted. An edge another source also records keeps that evidence.
func (a Adapter) RetractOwnership(ctx context.Context, id string) (bool, error) {
	if a.Repo == nil {
		return false, errors.New("missing OAM repository")
	}

	edge, err := a.Repo.FindEdgeById(ctx, id)
	if err != nil {
		return false, err
	}

	tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{})
	if err != nil && !emptyTagLookup(err) {
		return false, err
	}

	var ours []string
	others := 0
	for _, tag := range tags {
		if tag == nil || tag.Property == nil {
			continue
		}

		switch source(tag.Property) {
		case ai.InferenceSource:
			ours = append(ours, tag.ID)
		case "":
		default:
			others++
		}
	}
	if len(ours) == 0 {
		return false, fmt.Errorf("edge %s has no %s source", id, ai.InferenceSource)
	}
	if others > 0 {
		for _, tid := range ours {
			if err := a.Repo.DeleteEdgeTag(ctx, tid); err != nil {
				return false, err
			}
		}

		return false, nil
	}

	return true, a.Repo.DeleteEdge(ctx, id)
}
