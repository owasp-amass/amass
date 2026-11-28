// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"errors"
	"testing"
	"time"
)

// changingGraph reports the changes a test sets.
type changingGraph struct {
	*countingGraph
	changes GraphChanges
	err     error
	since   time.Time
}

func (c *changingGraph) GraphChanges(_ context.Context, since time.Time) (GraphChanges, error) {
	c.n("changes")
	c.since = since
	return c.changes, c.err
}

func TestLastingCacheDropsWhatChanged(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	inner := &changingGraph{countingGraph: &countingGraph{calls: map[string]int{}},
		changes: GraphChanges{Now: now}}
	lc := NewLastingCache(inner)

	read := func(g Graph) {
		t.Helper()
		for _, id := range []string{"x", "y"} {
			if _, err := g.GetAsset(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err := g.Edges(ctx, id, "out", "", time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := g.(EdgeEvidenceReader).EdgeEvidence(ctx, "e", 5); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(step string, assets, edges, edgeEvidence int) {
		t.Helper()
		if inner.calls["asset"] != assets || inner.calls["edges"] != edges ||
			inner.calls["edgeevidence"] != edgeEvidence {
			t.Errorf("%s: %d asset, %d edge and %d relation evidence reads, want %d, %d and %d", step,
				inner.calls["asset"], inner.calls["edges"], inner.calls["edgeevidence"], assets, edges,
				edgeEvidence)
		}
	}

	g, err := lc.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !inner.since.IsZero() {
		t.Errorf("the first refresh asked for changes since %v", inner.since)
	}
	read(g)
	expect("first read", 2, 2, 1)

	// nothing changed: every read is answered from memory
	inner.changes = GraphChanges{Now: now.Add(time.Minute)}
	if g, err = lc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(-changeOverlap); !inner.since.Equal(want) {
		t.Errorf("the refresh asked for changes since %v, want %v", inner.since, want)
	}
	read(g)
	expect("no changes", 2, 2, 1)

	// x changed: x and relation evidence are read again, y is not
	inner.changes = GraphChanges{Now: now.Add(2 * time.Minute), IDs: []string{"x"}}
	if g, err = lc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	read(g)
	expect("x changed", 3, 3, 2)

	// a deletion starts the cache over
	inner.changes = GraphChanges{Now: now.Add(3 * time.Minute), Deletions: 1}
	if g, err = lc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	read(g)
	expect("a deletion", 5, 5, 3)

	// a failed report answers from a cache for one request and starts over
	inner.err = errors.New("the store is unreachable")
	if g, err = lc.Refresh(ctx); err == nil || g == nil {
		t.Fatalf("a failed report returned %v, %v", g, err)
	}
	read(g)
	expect("a failed report", 7, 7, 4)

	inner.err = nil
	if _, err = lc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !inner.since.IsZero() {
		t.Errorf("the refresh after a failure asked for changes since %v", inner.since)
	}
}

func TestLastingCacheWithoutChangeReports(t *testing.T) {
	lc := NewLastingCache(&countingGraph{calls: map[string]int{}})
	g, err := lc.Refresh(context.Background())
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("a graph without change reports answered %v", err)
	}
	if _, ok := g.(*cachedGraph); !ok {
		t.Errorf("a graph without change reports is read as %T, not through a cache", g)
	}
}
