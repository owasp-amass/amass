// SPDX-License-Identifier: Apache-2.0
// Package oamrepo connects the AI graph tools to the existing Amass repository.
package oamrepo

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type Adapter struct{ Repo repository.Repository }

func (a Adapter) GetAsset(ctx context.Context, id string) (ai.Asset, error) {
	if a.Repo == nil {
		return ai.Asset{}, errors.New("missing OAM repository")
	}
	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return ai.Asset{}, err
	}
	return convert(ent)
}
func convert(e *dbt.Entity) (ai.Asset, error) {
	if e == nil || e.Asset == nil {
		return ai.Asset{}, errors.New("empty entity/asset")
	}
	return ai.Asset{ID: e.ID, Type: string(e.Asset.AssetType()), Key: e.Asset.Key(),
		Content: e.Asset, CreatedAt: e.CreatedAt, LastSeen: e.LastSeen}, nil
}
func knownAssetType(t string) bool {
	for _, item := range oam.AssetList {
		if string(item) == t {
			return true
		}
	}
	return false
}
func (a Adapter) FindAssets(ctx context.Context, t string, since time.Time, limit int) ([]ai.Asset, error) {
	if !knownAssetType(t) {
		return nil, fmt.Errorf("unknown OAM asset type %q", t)
	}
	ents, err := a.Repo.FindEntitiesByType(ctx, oam.AssetType(t), since, limit)
	if err != nil {
		return nil, err
	}
	if len(ents) > limit {
		ents = ents[:limit]
	}
	out := make([]ai.Asset, 0, len(ents))
	for _, ent := range ents {
		v, err := convert(ent)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (a Adapter) Edges(ctx context.Context, id, direction, label string, since time.Time) ([]ai.Relation, error) {
	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return nil, err
	}
	var labels []string
	if label != "" {
		labels = []string{label}
	}
	var found []ai.Relation
	convertEdges := func(edges []*dbt.Edge, dir string) error {
		for _, edge := range edges {
			if edge == nil || edge.Relation == nil || edge.FromEntity == nil || edge.ToEntity == nil {
				return errors.New("invalid edge")
			}
			if label != "" && edge.Relation.Label() != label {
				continue
			}
			found = append(found, ai.Relation{ID: edge.ID, FromID: edge.FromEntity.ID, ToID: edge.ToEntity.ID,
				Label: edge.Relation.Label(), Type: string(edge.Relation.RelationType()), Direction: dir,
				CreatedAt: edge.CreatedAt, LastSeen: edge.LastSeen})
		}
		return nil
	}
	if direction == "in" || direction == "both" {
		edges, err := a.Repo.IncomingEdges(ctx, ent, since, labels...)
		if err != nil {
			return nil, err
		}
		if err := convertEdges(edges, "in"); err != nil {
			return nil, err
		}
	}
	if direction == "out" || direction == "both" {
		edges, err := a.Repo.OutgoingEdges(ctx, ent, since, labels...)
		if err != nil {
			return nil, err
		}
		if err := convertEdges(edges, "out"); err != nil {
			return nil, err
		}
	}
	return found, nil
}
func (a Adapter) Evidence(ctx context.Context, id string, limit int) ([]ai.Evidence, error) {
	if ent, err := a.Repo.FindEntityById(ctx, id); err == nil {
		tags, err := a.Repo.FindEntityTags(ctx, ent, time.Time{})
		if err != nil {
			return nil, err
		}
		out := make([]ai.Evidence, 0)
		for _, tag := range tags {
			if tag == nil || tag.Property == nil {
				continue
			}
			if len(out) >= limit {
				break
			}
			out = append(out, ai.Evidence{ID: tag.ID, SubjectID: id, SourceID: source(tag.Property),
				Kind: string(tag.Property.PropertyType()), Property: tag.Property, LastSeen: tag.LastSeen})
		}
		return out, nil
	}
	edge, err := a.Repo.FindEdgeById(ctx, id)
	if err != nil {
		return nil, err
	}
	tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{})
	if err != nil {
		return nil, err
	}
	out := make([]ai.Evidence, 0)
	for _, tag := range tags {
		if tag == nil || tag.Property == nil {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, ai.Evidence{ID: tag.ID, SubjectID: id, SourceID: source(tag.Property),
			Kind: string(tag.Property.PropertyType()), Property: tag.Property, LastSeen: tag.LastSeen})
	}
	return out, nil
}

// Source identity is only assigned to explicitly typed provenance properties.
// Other properties are evidence but do not establish independent sources.
func source(p oam.Property) string {
	if p.PropertyType() != oam.SourceProperty {
		return ""
	}
	return p.Name()
}

var _ ai.Graph = Adapter{}

// AllowedRelation ensures that an inferred edge conforms to the existing OAM taxonomy.
func AllowedRelation(subject, label, object string) bool {
	// AI proposes SimpleRelation only in this initial implementation.
	return oam.ValidRelationship(oam.AssetType(subject), label, oam.SimpleRelation, oam.AssetType(object))
}

// EdgesLimited requires a repository that implements server-side SQL bounds.
// The current released asset-db dependency may not implement it yet; graph
// walks must fail closed until the bounded API is released or pinned.
func (a Adapter) EdgesLimited(ctx context.Context, id, direction, label string, since time.Time, limit int) ([]ai.Relation, bool, error) {
	if a.Repo == nil {
		return nil, false, errors.New("missing repository")
	}
	bounded, ok := a.Repo.(interface {
		ReadEdgesLimited(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, bool, error)
	})
	if !ok {
		return nil, false, errors.New("asset-db version lacks bounded edge reader; upgrade the repository dependency")
	}
	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return nil, false, err
	}
	var labels []string
	if label != "" {
		labels = []string{label}
	}
	edges, more, err := bounded.ReadEdgesLimited(ctx, ent, direction, since, limit, labels...)
	if err != nil {
		return nil, false, err
	}
	if len(edges) > limit {
		return nil, false, errors.New("repository violated bounded edge limit")
	}
	out := make([]ai.Relation, 0, len(edges))
	for _, e := range edges {
		if e == nil || e.Relation == nil || e.FromEntity == nil || e.ToEntity == nil {
			return nil, false, errors.New("malformed bounded edge")
		}
		dir := "out"
		if e.ToEntity.ID == id {
			dir = "in"
		}
		out = append(out, ai.Relation{ID: e.ID, FromID: e.FromEntity.ID, ToID: e.ToEntity.ID, Label: e.Relation.Label(), Type: string(e.Relation.RelationType()), Direction: dir, CreatedAt: e.CreatedAt, LastSeen: e.LastSeen})
	}
	return out, more, nil
}

var _ ai.BoundedGraph = Adapter{}


// LookupOrganizations performs bounded, typed lookups with a conservative
// punctuation fallback. It never scans the repository, and never silently
// selects among multiple plausible legal entities.
func (a Adapter) LookupOrganizations(ctx context.Context, name string, limit int) ([]ai.Asset, error) {
	if a.Repo == nil {
		return nil, errors.New("missing OAM repository")
	}
	name = strings.Join(strings.Fields(name), " ")
	if name == "" || len(name) > 256 || limit < 1 || limit > 10 {
		return nil, errors.New("invalid organization lookup parameters")
	}

	// Models sometimes remove a final period from a company name (e.g.,
	// "Inc." -> "Inc"). Try both exact forms using indexed content queries.
	// This is intentionally not fuzzy matching: other punctuation and
	// arbitrary string similarity are NOT accepted as an entity identity.
	variants := []string{name}
	if strings.HasSuffix(name, ".") {
		variants = append(variants, strings.TrimSuffix(name, "."))
	} else {
		variants = append(variants, name+".")
	}

	out := make([]ai.Asset, 0, limit)
	seen := make(map[string]bool, limit)
	for _, candidate := range variants {
		if candidate == "" || len(out) >= limit {
			break
		}
		remaining := limit - len(out)
		entities, err := a.Repo.FindEntitiesByContent(ctx, oam.Organization,
			time.Time{}, remaining, dbt.ContentFilters{"name": candidate})
		if err != nil {
			// PostgreSQL reports an empty content query as a sentinel error.
			// Other repository failures must never be mistaken for no matches.
			if strings.TrimSpace(err.Error()) == "zero entities found" {
				continue
			}
			return nil, err
		}
		if len(entities) > remaining {
			return nil, errors.New("repository exceeded organization lookup limit")
		}
		for _, entity := range entities {
			asset, err := convert(entity)
			if err != nil {
				return nil, err
			}
			if !seen[asset.ID] {
				seen[asset.ID] = true
				out = append(out, asset)
			}
		}
	}
	return out, nil
}

var _ ai.OrganizationLookup = Adapter{}


// Catalog derives permitted graph transitions from the OAM package.
type Catalog struct{}

// Relations enumerates actual OAM labels and relation types. Sorted so
// different providers and runs receive the same schema context.
func (Catalog) Relations() []ai.RelationshipSchema {
	var results []ai.RelationshipSchema
	for _, src := range oam.AssetList {
		for _, label := range oam.GetAssetOutgoingRelations(src) {
			for _, relType := range oam.RelationList {
				for _, dst := range oam.GetTransformAssetTypes(src, label, relType) {
					results = append(results, ai.RelationshipSchema{
						SourceType: string(src), Label: label,
						RelationType: string(relType), DestinationType: string(dst),
					})
				}
			}
		}
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.SourceType != b.SourceType { return a.SourceType < b.SourceType }
		if a.Label != b.Label { return a.Label < b.Label }
		if a.RelationType != b.RelationType { return a.RelationType < b.RelationType }
		return a.DestinationType < b.DestinationType
	})
	return results
}

var _ ai.SchemaCatalog = Catalog{}
