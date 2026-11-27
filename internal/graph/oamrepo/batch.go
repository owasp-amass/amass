// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	dbt "github.com/owasp-amass/asset-db/types"
)

// maxBatchIDs and maxBatchLabels are the most IDs and labels asset-db's
// batch reads take at once.
const (
	maxBatchIDs    = 1000
	maxBatchLabels = 64
)

// ReadStats counts an adapter's database reads and the time they took, so
// a lens run can be measured against a real database.
type ReadStats struct {
	mu    sync.Mutex
	calls map[string]int
	took  map[string]time.Duration
}

// record notes one read; a nil ReadStats records nothing.
func (s *ReadStats) record(method string, start time.Time) {
	if s == nil {
		return
	}

	d := time.Since(start)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls, s.took = map[string]int{}, map[string]time.Duration{}
	}

	s.calls[method]++
	s.took[method] += d
}

// methods returns the methods with recorded reads, sorted; the caller holds
// s.mu.
func (s *ReadStats) methods() []string {
	methods := make([]string, 0, len(s.calls))
	for m := range s.calls {
		methods = append(methods, m)
	}

	sort.Strings(methods)
	return methods
}

// Summary returns the reads recorded so far, their total time, and each
// method's reads as "method=n" in method order.
func (s *ReadStats) Summary() (int, time.Duration, string) {
	if s == nil {
		return 0, 0, ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	methods := s.methods()
	var calls int
	var took time.Duration
	parts := make([]string, 0, len(methods))
	for _, m := range methods {
		calls, took = calls+s.calls[m], took+s.took[m]
		parts = append(parts, fmt.Sprintf("%s=%d", m, s.calls[m]))
	}

	return calls, took, strings.Join(parts, " ")
}

// Write prints each method's reads, total and mean time.
func (s *ReadStats) Write(w io.Writer) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var calls int
	var took time.Duration
	for _, m := range s.methods() {
		n, d := s.calls[m], s.took[m]
		calls, took = calls+n, took+d
		_, _ = fmt.Fprintf(w, "%-14s %7d reads %10s total %10s mean\n", m, n, d.Round(time.Millisecond),
			(d / time.Duration(n)).Round(time.Microsecond))
	}

	_, _ = fmt.Fprintf(w, "%-14s %7d reads %10s total\n", "all", calls, took.Round(time.Millisecond))
}

// GetAssets reads many assets at once: with asset-db's FindEntitiesByIds
// when the repository has it, otherwise one at a time. An ID with no asset
// is absent from the result.
func (a Adapter) GetAssets(ctx context.Context, ids []string) (map[string]graph.Asset, error) {
	if a.Repo == nil {
		return nil, errors.New("missing OAM repository")
	}

	defer a.Stats.record("GetAssets", time.Now())

	out := make(map[string]graph.Asset, len(ids))
	batch, ok := a.Repo.(interface {
		FindEntitiesByIds(context.Context, []string) ([]*dbt.Entity, error)
	})
	if !ok {
		for _, id := range ids {
			if _, done := out[id]; done {
				continue
			}

			ent, err := a.Repo.FindEntityById(ctx, id)
			if err != nil {
				continue // absent, as with the batch read
			}
			if asset, err := convert(ent); err == nil {
				out[id] = asset
			}
		}

		return out, nil
	}

	for chunk := range slices.Chunk(ids, maxBatchIDs) {
		ents, err := batch.FindEntitiesByIds(ctx, chunk)
		if err != nil {
			return nil, err
		}
		for _, ent := range ents {
			asset, err := convert(ent)
			if err != nil {
				return nil, err
			}

			out[asset.ID] = asset
		}
	}

	return out, nil
}

var _ graph.AssetBatchReader = Adapter{}

// EdgesPerLabel reads an asset's edges in one direction with up to perLabel
// edges for each label: in one query with asset-db's ReadEdgesPerLabel when
// the repository has it, otherwise one EdgesLimited read per label. more
// names the OAM labels with edges beyond perLabel.
func (a Adapter) EdgesPerLabel(ctx context.Context, id, direction string, labels []string, since time.Time,
	perLabel int) ([]graph.Relation, []string, error) {
	if a.Repo == nil {
		return nil, nil, errors.New("missing repository")
	}

	reader, ok := a.Repo.(interface {
		ReadEdgesPerLabel(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, []string, error)
	})
	if !ok {
		return a.edgesEachLabel(ctx, id, direction, labels, since, perLabel)
	}

	defer a.Stats.record("EdgesPerLabel", time.Now())

	// A port relation may be stored under its own name (tcp_port_443), so a
	// read that wants "port", or too many labels to filter by, reads every
	// label and keeps the wanted ones.
	stored := labels
	if slices.Contains(labels, "port") || len(labels) > maxBatchLabels {
		stored = nil
	}

	edges, moreStored, err := reader.ReadEdgesPerLabel(ctx, &dbt.Entity{ID: id}, direction, since, perLabel, stored...)
	if err != nil {
		return nil, nil, err
	}

	want := map[string]bool{}
	for _, l := range labels {
		want[l] = true
	}

	// The OAM label of each stored label read, for the labels with more.
	schemaOf := map[string]string{}
	out := make([]graph.Relation, 0, len(edges))
	for _, e := range edges {
		if e == nil || e.Relation == nil || e.FromEntity == nil || e.ToEntity == nil {
			return nil, nil, errors.New("malformed labeled edge")
		}

		label := schemaLabel(e.Relation)
		schemaOf[e.Relation.Label()] = label
		if len(want) > 0 && !want[label] {
			continue
		}

		out = append(out, relationOf(e, id))
	}

	var more []string
	for _, l := range moreStored {
		label := l
		if s, ok := schemaOf[l]; ok {
			label = s
		}
		if (len(want) == 0 || want[label]) && !slices.Contains(more, label) {
			more = append(more, label)
		}
	}

	sort.Strings(more)
	return out, more, nil
}

var _ graph.LabeledEdgeReader = Adapter{}

// edgesEachLabel is EdgesPerLabel for a repository without the one-query
// read.
func (a Adapter) edgesEachLabel(ctx context.Context, id, direction string, labels []string, since time.Time,
	perLabel int) ([]graph.Relation, []string, error) {
	if len(labels) == 0 {
		return nil, nil, errors.New("this repository reads edges per label only for named labels")
	}

	var out []graph.Relation
	var more []string
	for _, l := range labels {
		edges, m, err := a.EdgesLimited(ctx, id, direction, l, since, perLabel)
		if err != nil {
			return nil, nil, err
		}

		out = append(out, edges...)
		if m {
			more = append(more, l)
		}
	}

	return out, more, nil
}

// relationOf converts a stored edge read for the entity id.
func relationOf(e *dbt.Edge, id string) graph.Relation {
	dir := "out"
	if e.ToEntity.ID == id {
		dir = "in"
	}

	return graph.Relation{ID: e.ID, FromID: e.FromEntity.ID, ToID: e.ToEntity.ID, Label: schemaLabel(e.Relation),
		Type: string(e.Relation.RelationType()), Direction: dir, Content: e.Relation, CreatedAt: e.CreatedAt,
		LastSeen: e.LastSeen}
}

// EdgesForAssets reads the edges of many assets in one direction with up to
// perAsset edges for each: in one query per batch with asset-db's
// ReadEdgesForEntities when the repository has it, otherwise one
// EdgesLimited read per asset.
func (a Adapter) EdgesForAssets(ctx context.Context, ids []string, direction string, since time.Time,
	perAsset int) (map[string][]graph.Relation, map[string]bool, error) {
	if a.Repo == nil {
		return nil, nil, errors.New("missing repository")
	}

	out := make(map[string][]graph.Relation, len(ids))
	more := map[string]bool{}
	reader, ok := a.Repo.(interface {
		ReadEdgesForEntities(context.Context, []string, string, time.Time, int, ...string) (map[string][]*dbt.Edge,
			[]string, error)
	})
	if !ok {
		for _, id := range ids {
			edges, m, err := a.EdgesLimited(ctx, id, direction, "", since, perAsset)
			if err != nil {
				return nil, nil, err
			}

			out[id] = edges
			if m {
				more[id] = true
			}
		}

		return out, more, nil
	}

	defer a.Stats.record("EdgesForAssets", time.Now())

	for chunk := range slices.Chunk(ids, maxBatchIDs) {
		read, partial, err := reader.ReadEdgesForEntities(ctx, chunk, direction, since, perAsset)
		if err != nil {
			return nil, nil, err
		}

		for id, edges := range read {
			if len(edges) > perAsset {
				return nil, nil, errors.New("repository violated bounded edge limit")
			}

			rels := make([]graph.Relation, 0, len(edges))
			for _, e := range edges {
				if e == nil || e.Relation == nil || e.FromEntity == nil || e.ToEntity == nil {
					return nil, nil, errors.New("malformed batched edge")
				}

				rels = append(rels, relationOf(e, id))
			}

			out[id] = rels
		}
		for _, id := range partial {
			more[id] = true
		}
	}

	return out, more, nil
}

var _ graph.MultiEdgeReader = Adapter{}
