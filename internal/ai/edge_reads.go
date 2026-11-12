// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"time"
)

// readEdges reads the edges of one asset in one direction with one label
// ("" for any), as completely as the graph and the caller's budget allow:
// page by page when the graph pages, otherwise one bounded read, otherwise
// an unbounded read. spend is called before each database read and returns
// false when the caller's read budget is spent. It stops after maxEdges
// edges. more reports edges left unread, by the budget, the cap or a graph
// that can only return one bounded page.
func readEdges(ctx context.Context, graph Graph, id, dir, label string, maxEdges int,
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
