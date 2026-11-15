// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// labeledGraph has 3 "a" edges and 1 "b" edge on asset r, and pages.
type labeledGraph struct {
	countingGraph
}

func (l *labeledGraph) all(label string) []Relation {
	n := map[string]int{"a": 3, "b": 1}[label]
	var out []Relation
	for i := 0; i < n; i++ {
		out = append(out, Relation{ID: fmt.Sprintf("%s%d", label, i), FromID: "r", ToID: fmt.Sprintf("%s-to-%d", label, i), Label: label})
	}
	return out
}

func (l *labeledGraph) EdgesPerLabel(_ context.Context, _, _ string, labels []string, _ time.Time, per int) ([]Relation, []string, error) {
	l.n("perlabel")
	var out []Relation
	var more []string
	for _, label := range labels {
		all := l.all(label)
		if len(all) > per {
			all, more = all[:per], append(more, label)
		}
		out = append(out, all...)
	}
	return out, more, nil
}

func (l *labeledGraph) EdgesPage(_ context.Context, _, _, label string, _ time.Time, cursor string, limit int) ([]Relation, string, error) {
	l.n("page")
	all := l.all(label)
	start := 0
	if cursor != "" {
		_, _ = fmt.Sscan(cursor, &start)
	}
	end := min(start+limit, len(all))
	next := ""
	if end < len(all) {
		next = fmt.Sprint(end)
	}
	return all[start:end], next, nil
}

func TestReadLabelsOneReadThenPagesWhatIsLeft(t *testing.T) {
	g := &labeledGraph{countingGraph{calls: map[string]int{}}}
	reads := 0
	spend := func() bool { reads++; return true }

	// Within one read's limit: one read for both labels.
	got, more, err := ReadLabels(context.Background(), g, "r", "out", []string{"a", "b"}, 10, spend)
	if err != nil || len(got["a"]) != 3 || len(got["b"]) != 1 || more["a"] || more["b"] || reads != 1 {
		t.Fatalf("got %v more %v reads %d err %v", got, more, reads, err)
	}

	// A cap below the edges: the first edges, marked partial.
	got, more, err = ReadLabels(context.Background(), g, "r", "out", []string{"a", "b"}, 2, spend)
	if err != nil || len(got["a"]) != 2 || !more["a"] || more["b"] {
		t.Fatalf("got %v more %v err %v", got, more, err)
	}

	// One label alone reads as ReadEdges does.
	got, _, err = ReadLabels(context.Background(), g, "r", "out", []string{"a"}, 10, spend)
	if err != nil || len(got["a"]) != 3 || g.calls["perlabel"] != 2 {
		t.Fatalf("got %v calls %v err %v", got, g.calls, err)
	}
}

func TestFarAssetsBatchesUnknownEnds(t *testing.T) {
	inner := &countingGraph{calls: map[string]int{}}
	edges := []Relation{{FromID: "r", ToID: "x"}, {FromID: "y", ToID: "r"}, {FromID: "r", ToID: "x"}, {FromID: "r", ToID: "known"}}
	read, err := FarAssets(context.Background(), inner, "r", edges, func(id string) bool { return id == "known" })
	if err != nil || len(read) != 2 || inner.calls["assets:x,y"] != 1 {
		t.Fatalf("read %v calls %v err %v", read, inner.calls, err)
	}
	a, err := AssetFrom(context.Background(), inner, read, "z")
	if err != nil || a.ID != "a" || inner.calls["asset"] != 1 {
		t.Fatalf("an asset not batched was not read alone: %v %v", a, inner.calls)
	}

	type plain struct{ Graph }
	if read, err := FarAssets(context.Background(), plain{inner}, "r", edges, nil); read != nil || err != nil {
		t.Fatal("a graph that cannot batch was batched")
	}
}
