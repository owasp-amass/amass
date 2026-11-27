// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdb "github.com/owasp-amass/amass/v5/internal/db"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
)

// AddSource records src as a source of an entity.
func AddSource(ctx context.Context, sess et.Session, ent *dbt.Entity, src *et.Source) {
	if ent == nil || src == nil {
		return
	}
	_, _ = sess.DB().CreateEntityProperty(ctx, ent, &general.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
}

// AddProperty stores a simple property on an entity.
func AddProperty(ctx context.Context, sess et.Session, ent *dbt.Entity, name, value string) {
	if ent == nil || name == "" || value == "" {
		return
	}
	_, _ = sess.DB().CreateEntityProperty(ctx, ent, &general.SimpleProperty{PropertyName: name,
		PropertyValue: value})
}

// AddEdgeProperty stores a simple property on an edge, such as the role or
// field that qualifies a relation.
func AddEdgeProperty(ctx context.Context, sess et.Session, edge *dbt.Edge, name, value string) {
	if edge == nil || name == "" || value == "" {
		return
	}
	_, _ = sess.DB().CreateEdgeProperty(ctx, edge, &general.SimpleProperty{PropertyName: name,
		PropertyValue: value})
}

// Relate creates the relation from one entity to another with src as its
// source, and returns the edge. An edge that already exists is returned with
// src added as one of its sources.
func Relate(ctx context.Context, sess et.Session, from *dbt.Entity, rel oam.Relation, to *dbt.Entity,
	src *et.Source) (*dbt.Edge, error) {
	if from == nil || to == nil || rel == nil {
		return nil, errors.New("the relation is missing an entity")
	}

	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
	if err != nil {
		return nil, err
	} else if edge == nil {
		return nil, errors.New("failed to create the edge")
	}

	if src != nil {
		if _, err := sess.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		}); err != nil {
			return edge, err
		}
	}
	return edge, nil
}

// Link creates a simple relation labeled label from one entity to another
// with src as its source, and returns the edge, or nil when it was not
// created.
func Link(ctx context.Context, sess et.Session, from *dbt.Entity, label string, to *dbt.Entity,
	src *et.Source) *dbt.Edge {
	edge, err := Relate(ctx, sess, from, &general.SimpleRelation{Name: label}, to, src)
	if err != nil && edge == nil {
		return nil
	}
	return edge
}

// Sourced reports whether src vouched for the edge since the time: whether the
// edge carries src's source property.
func Sourced(ctx context.Context, sess et.Session, edge *dbt.Edge, since time.Time, src *et.Source) bool {
	if edge == nil || src == nil {
		return false
	}

	tags, err := sess.DB().FindEdgeTags(ctx, edge, since, src.Name)
	if err != nil {
		return false
	}
	for _, tag := range tags {
		if _, ok := tag.Property.(*general.SourceProperty); ok {
			return true
		}
	}
	return false
}

// StoredFindings returns what an expansion handler found from an entity
// before, so a handler within its TTL can dispatch it again instead of asking
// its source: the entity's outgoing edges with a label that labels lists for
// an asset type the configuration matches, whose target was seen within that
// type's TTL (the transformation from the entity's type for the plugin) and,
// unless src is nil, that src vouched for.
func StoredFindings(e *et.Event, from *dbt.Entity, fromName, plugin string, m *config.Matches,
	labels map[string][]string, src *et.Source) []*Finding {
	fromType := string(from.Asset.AssetType())

	var rels []string
	sinces := make(map[string]time.Time)
	for atype, labs := range labels {
		if !m.IsMatch(atype) {
			continue
		}
		since, err := TTLStartTime(e.Session.Config(), fromType, atype, plugin)
		if err != nil {
			continue
		}
		sinces[atype] = since
		rels = append(rels, labs...)
	}
	if len(rels) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	edges, err := e.Session.DB().OutgoingEdges(ctx, from, time.Time{}, rels...)
	if err != nil || len(edges) == 0 {
		return nil
	}

	var findings []*Finding
	ends := amassdb.EdgeEnds(ctx, e.Session.DB(), edges, false)
	for _, edge := range edges {
		to, ok := ends[edge.ToEntity.ID]
		if !ok {
			continue
		}

		since, ok := sinces[string(to.Asset.AssetType())]
		if !ok || to.LastSeen.Before(since) {
			continue
		}
		if src != nil && !Sourced(ctx, e.Session, edge, since, src) {
			continue
		}

		findings = append(findings, &Finding{
			From:     from,
			FromName: fromName,
			To:       to,
			ToName:   to.Asset.Key(),
			Rel:      edge.Relation,
		})
	}
	return findings
}
