// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package oamrepo connects the AI graph tools to the existing Amass repository.
package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/asset-db/repository"
	neo4jrepo "github.com/owasp-amass/asset-db/repository/neo4j"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

type Adapter struct {
	Repo    repository.Repository
	Aliases []graph.OrganizationAlias
	// Neo4jDatabase names the Neo4j database when Repo is asset-db's Neo4j
	// repository; empty selects the server default. See Neo4jDatabaseName.
	Neo4jDatabase string
	// Stats, when set, counts the reads lenses make and their time.
	Stats *ReadStats
	// WithholdDocumentText replaces the findings a document model read, which
	// quote the document (graph.DocumentTextProperties), with a marker, for
	// a graph served to models the user has not allowed to read documents
	// (options.ai.documents.share_with_assistants). Counts stay visible.
	WithholdDocumentText bool
	// StrongContributions lets what assistants contributed be strong
	// evidence (options.ai.contributions.strong_evidence).
	StrongContributions bool
	// FixedHubs keeps every hub limit at the caller's fixed limit, not the
	// one the database's data derives (options.hubs.derive false).
	FixedHubs bool
}

// New is the adapter for repo under cfg's settings: its Neo4j database and
// its contribution policy.
func New(repo repository.Repository, cfg *config.Config) Adapter {
	a := Adapter{Repo: repo, Neo4jDatabase: Neo4jDatabaseName(cfg)}
	if cfg != nil {
		a.StrongContributions = cfg.AI.ContributionsStrong()
		a.FixedHubs = !cfg.DerivesHubs()
	}
	return a
}

// ContributionsStrong reports the adapter's contribution policy.
func (a Adapter) ContributionsStrong() bool { return a.StrongContributions }

var _ graph.ContributionPolicy = Adapter{}

func (a Adapter) GetAsset(ctx context.Context, id string) (graph.Asset, error) {
	if a.Repo == nil {
		return graph.Asset{}, errors.New("missing OAM repository")
	}

	defer a.Stats.record("GetAsset", time.Now())

	ent, err := a.Repo.FindEntityById(ctx, id)
	if err != nil {
		return graph.Asset{}, err
	}

	return convert(ent)
}

func convert(e *dbt.Entity) (graph.Asset, error) {
	if e == nil || e.Asset == nil {
		return graph.Asset{}, errors.New("empty entity/asset")
	}

	return graph.Asset{ID: e.ID, Type: string(e.Asset.AssetType()), Key: e.Asset.Key(),
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

func (a Adapter) FindAssets(ctx context.Context, t string, since time.Time, limit int) ([]graph.Asset, error) {
	if !knownAssetType(t) {
		return nil, fmt.Errorf("unknown OAM asset type %q", t)
	}

	if since.IsZero() {
		// The repositories require a start time to list a type; no stored
		// entity predates the Unix epoch.
		since = time.Unix(0, 0).UTC()
	}

	ents, err := a.Repo.FindEntitiesByType(ctx, oam.AssetType(t), since, limit)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(ents) > limit {
		ents = ents[:limit]
	}

	out := make([]graph.Asset, 0, len(ents))
	for _, ent := range ents {
		v, err := convert(ent)
		if err != nil {
			return nil, err
		}

		out = append(out, v)
	}

	return out, nil
}

func (a Adapter) Edges(ctx context.Context, id, direction, label string, since time.Time) ([]graph.Relation, error) {
	if a.Repo == nil {
		return nil, errors.New("missing OAM repository")
	}

	defer a.Stats.record("Edges", time.Now())

	// The edge readers use only the entity's ID, so the entity is not
	// fetched first; an ID with no entity has no edges.
	ent := &dbt.Entity{ID: id}
	labels := storedLabels(label)
	var found []graph.Relation
	convertEdges := func(edges []*dbt.Edge, dir string) error {
		for _, edge := range edges {
			if edge == nil || edge.Relation == nil || edge.FromEntity == nil || edge.ToEntity == nil {
				return errors.New("invalid edge")
			}
			if label != "" && schemaLabel(edge.Relation) != label {
				continue
			}

			found = append(found, graph.Relation{ID: edge.ID, FromID: edge.FromEntity.ID, ToID: edge.ToEntity.ID,
				Label: schemaLabel(edge.Relation), Type: string(edge.Relation.RelationType()), Direction: dir,
				Content: edge.Relation, CreatedAt: edge.CreatedAt, LastSeen: edge.LastSeen})
		}

		return nil
	}
	// asset-db reports an entity with no matching edges as an error.
	if direction == "in" || direction == "both" {
		edges, err := a.Repo.IncomingEdges(ctx, ent, since, labels...)
		if err != nil && !emptyEdgeLookup(err) {
			return nil, err
		}
		if err := convertEdges(edges, "in"); err != nil {
			return nil, err
		}
	}
	if direction == "out" || direction == "both" {
		edges, err := a.Repo.OutgoingEdges(ctx, ent, since, labels...)
		if err != nil && !emptyEdgeLookup(err) {
			return nil, err
		}
		if err := convertEdges(edges, "out"); err != nil {
			return nil, err
		}
	}

	return found, nil
}

func (a Adapter) Evidence(ctx context.Context, id string, limit int) ([]graph.Evidence, error) {
	defer a.Stats.record("Evidence", time.Now())

	if ent, err := a.Repo.FindEntityById(ctx, id); err == nil {
		tags, err := a.Repo.FindEntityTags(ctx, ent, time.Time{})
		if emptyTagLookup(err) {
			return []graph.Evidence{}, nil
		}
		if err != nil {
			return nil, err
		}

		out := make([]graph.Evidence, 0)
		for _, tag := range tags {
			if tag == nil || tag.Property == nil {
				continue
			}
			if len(out) >= limit {
				break
			}

			out = append(out, graph.Evidence{ID: tag.ID, SubjectID: id, SourceID: source(tag.Property),
				Kind: string(tag.Property.PropertyType()), Property: a.visible(tag.ID, tag.Property),
				LastSeen: tag.LastSeen})
		}

		return out, nil
	}

	edge, err := a.Repo.FindEdgeById(ctx, id)
	if err != nil {
		return nil, err
	}

	tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{})
	if emptyTagLookup(err) {
		return []graph.Evidence{}, nil
	}
	if err != nil {
		return nil, err
	}

	out := make([]graph.Evidence, 0)
	for _, tag := range tags {
		if tag == nil || tag.Property == nil {
			continue
		}
		if len(out) >= limit {
			break
		}

		out = append(out, graph.Evidence{ID: tag.ID, SubjectID: id, SourceID: source(tag.Property),
			Kind: string(tag.Property.PropertyType()), Property: tag.Property, LastSeen: tag.LastSeen})
	}

	return out, nil
}

// emptyTagLookup recognizes only exact repository-specific empty-result
// messages. Asset Database currently returns ordinary errors for missing
// tags instead of a shared sentinel. Do not treat arbitrary lookup errors
// as absence: storage, authentication, and decoding failures remain fatal.
func emptyTagLookup(err error) bool {
	if err == nil {
		return false
	}
	switch strings.TrimSpace(err.Error()) {
	case "no tags found for edge", // sqlite
		"no tags found for entity", // postgres (edge-tag reader)
		"no edge tags found",       // neo4j
		"no entity tags found",     // neo4j
		"zero tags found":          // neo4j
		return true
	}

	return false
}

// createEdge stores an edge between two entities. An entity read as the far
// end of another edge can carry only its ID; the Neo4j repository needs each
// end's asset to check the relationship, so such an end is read first.
func (a Adapter) createEdge(ctx context.Context, edge *dbt.Edge) (*dbt.Edge, error) {
	for _, end := range []**dbt.Entity{&edge.FromEntity, &edge.ToEntity} {
		if *end == nil || (*end).Asset != nil {
			continue
		}

		full, err := a.Repo.FindEntityById(ctx, (*end).ID)
		if err != nil {
			return nil, fmt.Errorf("entity %s: %w", (*end).ID, err)
		}

		*end = full
	}

	return a.Repo.CreateEdge(ctx, edge)
}

// EdgeEvidence always queries the relation namespace. Entity and edge
// identifiers may be identical; a generic FindEntityById-first lookup cannot
// safely be used for source-level relationship attribution.
func (a Adapter) EdgeEvidence(ctx context.Context, id string, limit int) ([]graph.Evidence, error) {
	if a.Repo == nil {
		return nil, errors.New("missing OAM repository")
	}
	if id == "" || limit < 1 || limit > 500 {
		return nil, errors.New("invalid edge evidence query or limit")
	}

	edge, err := a.Repo.FindEdgeById(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("resolve exact edge for evidence: %w", err)
	}

	tags, err := a.Repo.FindEdgeTags(ctx, edge, time.Time{})
	if emptyTagLookup(err) {
		return []graph.Evidence{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read edge %s provenance tags: %w", id, err)
	}

	out := make([]graph.Evidence, 0, min(len(tags), limit))
	for _, tag := range tags {
		if tag == nil || tag.Property == nil {
			continue
		}
		if len(out) >= limit {
			break
		}

		out = append(out, graph.Evidence{ID: tag.ID, SubjectID: id, SourceID: source(tag.Property),
			Kind: string(tag.Property.PropertyType()), Property: tag.Property, LastSeen: tag.LastSeen})
	}

	return out, nil
}

var _ graph.EdgeEvidenceReader = Adapter{}

// Source identity is only assigned to explicitly typed provenance properties.
// Other properties are evidence but do not establish independent sources.
func source(p oam.Property) string {
	if p.PropertyType() != oam.SourceProperty {
		return ""
	}

	return p.Name()
}

var _ graph.Graph = Adapter{}

// schemaLabel is the OAM schema label of a stored relation. A port
// relation is stored under its own name (tcp_port_443) but is the "port"
// relationship in OAM, as asset-db treats it when validating an edge.
func schemaLabel(rel oam.Relation) string {
	if rel.RelationType() == oam.PortRelation {
		return "port"
	}

	return rel.Label()
}

// storedLabels returns the stored labels to filter an edge read by, for an
// OAM schema label. Port relations are stored under their own names, so a
// "port" read is filtered after reading.
func storedLabels(label string) []string {
	if label == "" || label == "port" {
		return nil
	}

	return []string{label}
}

// AllowedRelation ensures that an inferred edge conforms to the existing OAM taxonomy.
func AllowedRelation(subject, label, object string) bool {
	// AI proposes SimpleRelation only in this initial implementation.
	return oam.ValidRelationship(oam.AssetType(subject), label, oam.SimpleRelation, oam.AssetType(object))
}

// EdgesLimited requires a repository that bounds edge reads on the server.
// SQLite and PostgreSQL need asset-db's ReadEdgesLimited (not yet in the
// released asset-db); Neo4j is bounded here with a LIMIT Cypher query over
// released asset-db APIs. Any other repository fails closed.
func (a Adapter) EdgesLimited(ctx context.Context, id, direction, label string, since time.Time, limit int) ([]graph.Relation, bool, error) {
	if a.Repo == nil {
		return nil, false, errors.New("missing repository")
	}

	bounded, ok := a.Repo.(interface {
		ReadEdgesLimited(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, bool, error)
	})
	neo, isNeo := a.Repo.(*neo4jrepo.NeoRepository)
	if !ok && !isNeo {
		return nil, false, errors.New("asset-db version lacks bounded edge reader; upgrade the repository dependency")
	}

	defer a.Stats.record("EdgesLimited", time.Now())

	// The edge readers use only the entity's ID, so the entity is not
	// fetched: that saved two queries on every read.
	ent := &dbt.Entity{ID: id}
	labels := storedLabels(label)
	var edges []*dbt.Edge
	var more bool
	var err error
	if ok {
		edges, more, err = bounded.ReadEdgesLimited(ctx, ent, direction, since, limit, labels...)
	} else {
		edges, more, err = neo4jEdgesLimited(ctx, neo, a.Neo4jDatabase, ent, direction, since, limit, labels...)
	}
	if err != nil {
		return nil, false, err
	}
	if len(edges) > limit {
		return nil, false, errors.New("repository violated bounded edge limit")
	}

	out := make([]graph.Relation, 0, len(edges))
	for _, e := range edges {
		if e == nil || e.Relation == nil || e.FromEntity == nil || e.ToEntity == nil {
			return nil, false, errors.New("malformed bounded edge")
		}

		if label != "" && schemaLabel(e.Relation) != label {
			continue
		}

		dir := "out"
		if e.ToEntity.ID == id {
			dir = "in"
		}

		out = append(out,
			graph.Relation{
				ID:        e.ID,
				FromID:    e.FromEntity.ID,
				ToID:      e.ToEntity.ID,
				Label:     schemaLabel(e.Relation),
				Type:      string(e.Relation.RelationType()),
				Direction: dir,
				Content:   e.Relation,
				CreatedAt: e.CreatedAt,
				LastSeen:  e.LastSeen,
			})
	}

	return out, more, nil
}

var _ graph.BoundedGraph = Adapter{}

// EdgesPage reads the page of edges after cursor, newest first, so a lens
// can read past the first EdgesLimited page. cursor is "" for the first
// page; the returned cursor is "" after the last one. SQLite and PostgreSQL
// page in asset-db (ReadEdgesPage); Neo4j pages here.
func (a Adapter) EdgesPage(ctx context.Context, id, direction, label string, since time.Time, cursor string, limit int) ([]graph.Relation, string, error) {
	if a.Repo == nil {
		return nil, "", errors.New("missing repository")
	}

	var after *dbt.EdgeCursor
	if cursor != "" {
		after = &dbt.EdgeCursor{}
		if err := json.Unmarshal([]byte(cursor), after); err != nil {
			return nil, "", fmt.Errorf("invalid edge cursor: %w", err)
		}
	}

	defer a.Stats.record("EdgesPage", time.Now())
	ent := &dbt.Entity{ID: id}
	pager, ok := a.Repo.(interface {
		ReadEdgesPage(context.Context, *dbt.Entity, string, time.Time, *dbt.EdgeCursor, int, ...string) ([]*dbt.Edge, *dbt.EdgeCursor, error)
	})
	neo, isNeo := a.Repo.(*neo4jrepo.NeoRepository)

	labels := storedLabels(label)
	var edges []*dbt.Edge
	var next *dbt.EdgeCursor
	var err error
	switch {
	case ok:
		edges, next, err = pager.ReadEdgesPage(ctx, ent, direction, since, after, limit, labels...)
	case isNeo:
		edges, next, err = neo4jEdgesPage(ctx, neo, a.Neo4jDatabase, ent, direction, since, after, limit, labels...)
	default:
		return nil, "", errors.New("asset-db version lacks paged edge reads; upgrade the repository dependency")
	}
	if err != nil {
		return nil, "", err
	}
	if len(edges) > limit {
		return nil, "", errors.New("repository violated bounded edge limit")
	}

	out := make([]graph.Relation, 0, len(edges))
	for _, e := range edges {
		if e == nil || e.Relation == nil || e.FromEntity == nil || e.ToEntity == nil {
			return nil, "", errors.New("malformed paged edge")
		}
		if label != "" && schemaLabel(e.Relation) != label {
			continue
		}

		dir := "out"
		if e.ToEntity.ID == id {
			dir = "in"
		}

		out = append(out, graph.Relation{ID: e.ID, FromID: e.FromEntity.ID, ToID: e.ToEntity.ID,
			Label: schemaLabel(e.Relation), Type: string(e.Relation.RelationType()), Direction: dir,
			Content: e.Relation, CreatedAt: e.CreatedAt, LastSeen: e.LastSeen})
	}

	if next == nil {
		return out, "", nil
	}

	raw, err := json.Marshal(next)
	if err != nil {
		return nil, "", err
	}

	return out, string(raw), nil
}

var _ graph.PagedGraph = Adapter{}

var _ graph.OrganizationResolver = Adapter{}

var _ graph.OrganizationLookup = Adapter{}

var _ graph.SchemaCatalog = Catalog{}

var _ graph.AttributionCatalog = Catalog{}

var _ graph.SemanticsCatalog = Catalog{}

var _ graph.AssetSearchCatalog = Catalog{}

var _ graph.AssetResolver = Adapter{}

// visible is the property a reader may see: a document text property's value
// is replaced by a marker naming the tag, so each stays distinct and countable,
// when document text is withheld.
func (a Adapter) visible(tagID string, p oam.Property) oam.Property {
	if !a.WithholdDocumentText {
		return p
	}
	sp, ok := p.(*oamgen.SimpleProperty)
	if !ok || !graph.IsDocumentTextProperty(sp.PropertyName) {
		return p
	}
	return &oamgen.SimpleProperty{PropertyName: sp.PropertyName, PropertyValue: graph.WithheldDocumentText(tagID)}
}
