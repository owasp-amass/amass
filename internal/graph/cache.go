// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// fullGraph is every reader a lens may use. Only a graph offering all of
// them is cached, so wrapping never hides or adds a capability.
type fullGraph interface {
	Graph
	BoundedGraph
	PagedGraph
	EdgeEvidenceReader
	AssetResolver
	OrganizationLookup
	OrganizationResolver
	AssetBatchReader
	LabeledEdgeReader
	MultiEdgeReader
}

// maxCached bounds the reads one cached graph keeps.
const maxCached = 500000

// Cached returns g wrapped so that repeated reads of the same asset, edges
// or evidence are answered from memory: a lens built from other lenses
// walks the same footprint several times. It is meant for one request; the
// database is not re-read, so writes made meanwhile are not seen. A graph
// that lacks any optional reader is returned unwrapped.
func Cached(g Graph) Graph {
	if _, done := g.(*cachedGraph); done {
		return g
	}

	full, ok := g.(fullGraph)
	if !ok {
		return g
	}

	return &cachedGraph{inner: full, entries: map[string]any{}}
}

type cachedGraph struct {
	inner   fullGraph
	mu      sync.Mutex
	entries map[string]any
}

type edgesResult struct {
	edges []Relation
	more  bool
	next  string
}

func (c *cachedGraph) get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[key]
	return v, ok
}

func (c *cachedGraph) put(key string, v any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) < maxCached {
		c.entries[key] = v
	}
}

func (c *cachedGraph) GetAsset(ctx context.Context, id string) (Asset, error) {
	key := "a\x00" + id
	if v, ok := c.get(key); ok {
		return v.(Asset), nil
	}

	a, err := c.inner.GetAsset(ctx, id)
	if err == nil {
		c.put(key, a)
	}

	return a, err
}

func (c *cachedGraph) FindAssets(ctx context.Context, kind string, since time.Time, limit int) ([]Asset, error) {
	return c.inner.FindAssets(ctx, kind, since, limit)
}

func (c *cachedGraph) Edges(ctx context.Context, id, dir, label string, since time.Time) ([]Relation, error) {
	key := fmt.Sprintf("e\x00%s\x00%s\x00%s\x00%d", id, dir, label, since.UnixNano())
	if v, ok := c.get(key); ok {
		return slices.Clone(v.(edgesResult).edges), nil
	}

	edges, err := c.inner.Edges(ctx, id, dir, label, since)
	if err == nil {
		c.put(key, edgesResult{edges: edges})
	}

	return edges, err
}

func (c *cachedGraph) EdgesLimited(ctx context.Context, id, dir, label string, since time.Time,
	limit int) ([]Relation, bool, error) {
	key := fmt.Sprintf("l\x00%s\x00%s\x00%s\x00%d\x00%d", id, dir, label, since.UnixNano(), limit)
	if v, ok := c.get(key); ok {
		r := v.(edgesResult)
		return slices.Clone(r.edges), r.more, nil
	}

	edges, more, err := c.inner.EdgesLimited(ctx, id, dir, label, since, limit)
	if err == nil {
		c.put(key, edgesResult{edges: edges, more: more})
	}

	return edges, more, err
}

func (c *cachedGraph) EdgesPage(ctx context.Context, id, dir, label string, since time.Time, cursor string,
	limit int) ([]Relation, string, error) {
	key := fmt.Sprintf("p\x00%s\x00%s\x00%s\x00%d\x00%s\x00%d", id, dir, label, since.UnixNano(), cursor, limit)
	if v, ok := c.get(key); ok {
		r := v.(edgesResult)
		return slices.Clone(r.edges), r.next, nil
	}

	edges, next, err := c.inner.EdgesPage(ctx, id, dir, label, since, cursor, limit)
	if err == nil {
		c.put(key, edgesResult{edges: edges, next: next})
	}

	return edges, next, err
}

func (c *cachedGraph) Evidence(ctx context.Context, id string, limit int) ([]Evidence, error) {
	key := fmt.Sprintf("v\x00%s\x00%d", id, limit)
	if v, ok := c.get(key); ok {
		return slices.Clone(v.([]Evidence)), nil
	}

	ev, err := c.inner.Evidence(ctx, id, limit)
	if err == nil {
		c.put(key, ev)
	}

	return ev, err
}

func (c *cachedGraph) EdgeEvidence(ctx context.Context, id string, limit int) ([]Evidence, error) {
	key := fmt.Sprintf("x\x00%s\x00%d", id, limit)
	if v, ok := c.get(key); ok {
		return slices.Clone(v.([]Evidence)), nil
	}

	ev, err := c.inner.EdgeEvidence(ctx, id, limit)
	if err == nil {
		c.put(key, ev)
	}

	return ev, err
}

func (c *cachedGraph) ResolveAsset(ctx context.Context, s AssetSelector, limit int) (AssetResolution, error) {
	return c.inner.ResolveAsset(ctx, s, limit)
}

func (c *cachedGraph) LookupOrganizations(ctx context.Context, name string, limit int) ([]Asset, error) {
	return c.inner.LookupOrganizations(ctx, name, limit)
}

func (c *cachedGraph) ResolveOrganizations(ctx context.Context, q OrganizationQuery, limit int) (OrganizationResolution, error) {
	return c.inner.ResolveOrganizations(ctx, q, limit)
}

// ContributionsStrong passes on the inner graph's contribution policy.
func (c *cachedGraph) ContributionsStrong() bool { return ContributionsStrong(c.inner) }

// HubRule passes on the inner graph's hub rules, which keep their own
// cache.
func (c *cachedGraph) HubRule(ctx context.Context, src HubSource, fallback int) HubRule {
	return SourceHubRule(ctx, c.inner, src, fallback)
}

// StepsFrom passes a step read to the inner graph, uncached: a walk reads
// each round's frontier once.
func (c *cachedGraph) StepsFrom(ctx context.Context, ids []string, steps []Step) ([]Relation, error) {
	if r, ok := c.inner.(StepReader); ok {
		return r.StepsFrom(ctx, ids, steps)
	}
	return nil, ErrStepsUnsupported
}

// valueSearcher is the value search a lens finds on its graph (its
// ValueSearcher), declared here by its methods.
type valueSearcher interface {
	FindByTagValue(ctx context.Context, assetType, name, value string, contains bool, limit int) ([]Asset, bool, error)
	FindByAttribute(ctx context.Context, assetType, key, value string, contains bool, limit int) ([]Asset, bool, error)
}

// FindByTagValue passes a value search to the inner graph, uncached, so
// wrapping a graph never hides its value searches.
func (c *cachedGraph) FindByTagValue(ctx context.Context, assetType, name, value string, contains bool,
	limit int) ([]Asset, bool, error) {
	if vs, ok := c.inner.(valueSearcher); ok {
		return vs.FindByTagValue(ctx, assetType, name, value, contains, limit)
	}
	return nil, false, ErrUnsupported
}

// FindByAttribute passes an attribute search to the inner graph, uncached.
func (c *cachedGraph) FindByAttribute(ctx context.Context, assetType, key, value string, contains bool,
	limit int) ([]Asset, bool, error) {
	if vs, ok := c.inner.(valueSearcher); ok {
		return vs.FindByAttribute(ctx, assetType, key, value, contains, limit)
	}
	return nil, false, ErrUnsupported
}

func (c *cachedGraph) GetAssets(ctx context.Context, ids []string) (map[string]Asset, error) {
	out := make(map[string]Asset, len(ids))
	var missing []string
	asked := map[string]bool{}
	for _, id := range ids {
		if v, ok := c.get("a\x00" + id); ok {
			out[id] = v.(Asset)
		} else if !asked[id] {
			asked[id] = true
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return out, nil
	}

	found, err := c.inner.GetAssets(ctx, missing)
	if err != nil {
		return nil, err
	}
	for id, a := range found {
		c.put("a\x00"+id, a)
		out[id] = a
	}

	return out, nil
}

func (c *cachedGraph) EdgesPerLabel(ctx context.Context, id, dir string, labels []string, since time.Time,
	perLabel int) ([]Relation, []string, error) {
	key := fmt.Sprintf("b\x00%s\x00%s\x00%s\x00%d\x00%d", id, dir, strings.Join(labels,
		","), since.UnixNano(), perLabel)
	if v, ok := c.get(key); ok {
		r := v.(labeledResult)
		return slices.Clone(r.edges), slices.Clone(r.more), nil
	}

	edges, more, err := c.inner.EdgesPerLabel(ctx, id, dir, labels, since, perLabel)
	if err == nil {
		c.put(key, labeledResult{edges: edges, more: more})
	}

	return slices.Clone(edges), slices.Clone(more), err
}

type labeledResult struct {
	edges []Relation
	more  []string
}

// EdgesForAssets reads the edges of the assets not already read and keeps
// each asset's result as its EdgesLimited read, so a later bounded read of
// one of them is answered from memory.
func (c *cachedGraph) EdgesForAssets(ctx context.Context, ids []string, dir string, since time.Time,
	perAsset int) (map[string][]Relation, map[string]bool, error) {
	key := func(id string) string {
		return fmt.Sprintf("l\x00%s\x00%s\x00%s\x00%d\x00%d", id, dir, "", since.UnixNano(), perAsset)
	}

	out := make(map[string][]Relation, len(ids))
	more := map[string]bool{}
	var missing []string
	asked := map[string]bool{}
	for _, id := range ids {
		if v, ok := c.get(key(id)); ok {
			r := v.(edgesResult)
			out[id] = slices.Clone(r.edges)
			if r.more {
				more[id] = true
			}
		} else if !asked[id] {
			asked[id] = true
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return out, more, nil
	}

	read, partial, err := c.inner.EdgesForAssets(ctx, missing, dir, since, perAsset)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range missing {
		c.put(key(id), edgesResult{edges: read[id], more: partial[id]})
		out[id] = slices.Clone(read[id])
		if partial[id] {
			more[id] = true
		}
	}

	return out, more, nil
}
