// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"time"
)

// ReadEdges reads the edges of one asset in one direction with one label
// ("" for any), as completely as the graph and the caller's budget allow:
// page by page when the graph pages, otherwise one bounded read, otherwise
// an unbounded read. spend is called before each database read and returns
// false when the caller's read budget is spent. It stops after maxEdges
// edges. more reports edges left unread, by the budget, the cap or a graph
// that can only return one bounded page.
func ReadEdges(ctx context.Context, graph Graph, id, dir, label string, maxEdges int,
	spend func() bool) ([]Relation, bool, error) {
	if pager, ok := graph.(PagedGraph); ok {
		var out []Relation
		cursor := ""
		for {
			if !spend() {
				return out, true, nil
			}

			edges, next, err := pager.EdgesPage(ctx, id, dir, label, time.Time{}, cursor,
				min(MaxEdgeRead, maxEdges-len(out)))
			if err != nil {
				return nil, false, err
			}

			out = append(out, edges...)
			if next == "" {
				return out, false, nil
			}
			if len(out) >= maxEdges {
				return out, true, nil
			}

			cursor = next
		}
	}

	if !spend() {
		return nil, true, nil
	}
	if b, ok := graph.(BoundedGraph); ok {
		return b.EdgesLimited(ctx, id, dir, label, time.Time{}, min(MaxEdgeRead, maxEdges))
	}

	edges, err := graph.Edges(ctx, id, dir, label, time.Time{})
	return edges, false, err
}

// ReadLabels reads the edges of one asset in one direction for each of
// labels, as ReadEdges does for each label on its own. When the graph is a
// LabeledEdgeReader, every label's first edges come in one read and only a
// label with more is then read alone. more names the labels left partial.
func ReadLabels(ctx context.Context, graph Graph, id, dir string, labels []string, maxEdges int,
	spend func() bool) (map[string][]Relation, map[string]bool, error) {
	out := make(map[string][]Relation, len(labels))
	more := map[string]bool{}
	lr, ok := graph.(LabeledEdgeReader)
	if !ok || len(labels) < 2 {
		for _, l := range labels {
			edges, m, err := ReadEdges(ctx, graph, id, dir, l, maxEdges, spend)
			if err != nil {
				return nil, nil, err
			}

			out[l], more[l] = edges, m
		}

		return out, more, nil
	}

	if !spend() {
		for _, l := range labels {
			more[l] = true
		}

		return out, more, nil
	}

	edges, partial, err := lr.EdgesPerLabel(ctx, id, dir, labels, time.Time{}, min(MaxEdgeRead, maxEdges))
	if err != nil {
		return nil, nil, err
	}
	for _, e := range edges {
		out[e.Label] = append(out[e.Label], e)
	}
	for _, l := range partial {
		if maxEdges <= MaxEdgeRead {
			more[l] = true
			continue
		}

		// Read the label alone, past the first edges, up to maxEdges.
		all, m, err := ReadEdges(ctx, graph, id, dir, l, maxEdges, spend)
		if err != nil {
			return nil, nil, err
		}

		out[l], more[l] = all, m
	}

	return out, more, nil
}
