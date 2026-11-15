// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"strings"
	"testing"
	"time"
)

type countingGraph struct{ calls map[string]int }

func (c *countingGraph) n(k string) { c.calls[k]++ }
func (c *countingGraph) GetAsset(context.Context, string) (Asset, error) {
	c.n("asset")
	return Asset{ID: "a"}, nil
}
func (c *countingGraph) FindAssets(context.Context, string, time.Time, int) ([]Asset, error) {
	c.n("find")
	return nil, nil
}
func (c *countingGraph) Edges(context.Context, string, string, string, time.Time) ([]Relation, error) {
	c.n("edges")
	return []Relation{{ID: "e"}}, nil
}
func (c *countingGraph) Evidence(context.Context, string, int) ([]Evidence, error) {
	c.n("evidence")
	return []Evidence{{ID: "v"}}, nil
}
func (c *countingGraph) EdgesLimited(_ context.Context, _, _, _ string, _ time.Time, limit int) ([]Relation, bool, error) {
	c.n("limited")
	return []Relation{{ID: "e"}}, limit < 10, nil
}
func (c *countingGraph) EdgesPage(context.Context, string, string, string, time.Time, string, int) ([]Relation, string, error) {
	c.n("page")
	return []Relation{{ID: "e"}}, "next", nil
}
func (c *countingGraph) EdgeEvidence(context.Context, string, int) ([]Evidence, error) {
	c.n("edgeevidence")
	return nil, nil
}
func (c *countingGraph) ResolveAsset(context.Context, AssetSelector, int) (AssetResolution, error) {
	c.n("resolve")
	return AssetResolution{}, nil
}
func (c *countingGraph) LookupOrganizations(context.Context, string, int) ([]Asset, error) {
	c.n("lookup")
	return nil, nil
}
func (c *countingGraph) ResolveOrganizations(context.Context, OrganizationQuery, int) (OrganizationResolution, error) {
	c.n("resolveorg")
	return OrganizationResolution{}, nil
}
func (c *countingGraph) GetAssets(_ context.Context, ids []string) (map[string]Asset, error) {
	c.n("assets")
	c.calls["assets:"+strings.Join(ids, ",")]++
	out := map[string]Asset{}
	for _, id := range ids {
		if id != "missing" {
			out[id] = Asset{ID: id}
		}
	}
	return out, nil
}
func (c *countingGraph) EdgesPerLabel(context.Context, string, string, []string, time.Time, int) ([]Relation, []string, error) {
	c.n("perlabel")
	return []Relation{{ID: "e"}}, []string{"node"}, nil
}

func TestCachedGraphReadsOnce(t *testing.T) {
	inner := &countingGraph{calls: map[string]int{}}
	g := Cached(inner)
	if Cached(g) != g {
		t.Error("a cached graph was wrapped again")
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _ = g.GetAsset(ctx, "a")
		_, _ = g.Edges(ctx, "a", "out", "", time.Time{})
		_, _ = g.Evidence(ctx, "a", 10)
		_, more, _ := g.(BoundedGraph).EdgesLimited(ctx, "a", "out", "x", time.Time{}, 5)
		if !more {
			t.Error("the limited read's more flag was lost")
		}
		_, next, _ := g.(PagedGraph).EdgesPage(ctx, "a", "out", "x", time.Time{}, "", 5)
		if next != "next" {
			t.Error("the page cursor was lost")
		}
		_, labels, _ := g.(LabeledEdgeReader).EdgesPerLabel(ctx, "a", "out", []string{"node"}, time.Time{}, 5)
		if len(labels) != 1 || labels[0] != "node" {
			t.Error("the labels with more were lost")
		}
	}
	for _, k := range []string{"asset", "edges", "evidence", "limited", "page", "perlabel"} {
		if inner.calls[k] != 1 {
			t.Errorf("%s read %d times", k, inner.calls[k])
		}
	}
	// Different arguments are different reads.
	_, _, _ = g.(BoundedGraph).EdgesLimited(ctx, "a", "out", "x", time.Time{}, 50)
	if inner.calls["limited"] != 2 {
		t.Errorf("a different limit was answered from the cache")
	}
	// A returned slice can be changed without changing the cache.
	edges, _ := g.Edges(ctx, "a", "out", "", time.Time{})
	edges[0].ID = "changed"
	if again, _ := g.Edges(ctx, "a", "out", "", time.Time{}); again[0].ID != "e" {
		t.Error("the cache returned a shared slice")
	}
}

// A batch read asks only for the assets not already read.
func TestCachedGraphBatchReadsOnlyMissing(t *testing.T) {
	inner := &countingGraph{calls: map[string]int{}}
	cached := Cached(inner)
	g := cached.(AssetBatchReader)
	ctx := context.Background()
	if _, err := cached.GetAsset(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	got, err := g.GetAssets(ctx, []string{"a", "b", "missing", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["b"].ID != "b" {
		t.Errorf("got %v", got)
	}
	if inner.calls["assets:b,missing"] != 1 {
		t.Errorf("the batch read asked for %v", inner.calls)
	}
	if _, err := g.GetAssets(ctx, []string{"a", "b"}); err != nil || inner.calls["assets"] != 1 {
		t.Errorf("cached assets were read again: %v", inner.calls)
	}
}

// A graph without every optional reader is not wrapped, so no capability
// appears or disappears.
func TestCachedLeavesPartialGraphs(t *testing.T) {
	type partial struct{ Graph }
	p := partial{}
	if _, wrapped := Cached(p).(*cachedGraph); wrapped {
		t.Error("a partial graph was wrapped")
	}
}
