// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// PagedVendorGraph adds paged edge reads to the vendor fixture; the cursor
// is the offset of the next edge in stored order.
type PagedVendorGraph struct {
	VendorGraph
	Pages *int
}

func (g PagedVendorGraph) EdgesPage(ctx context.Context, id, dir, label string, since time.Time, cursor string,
	limit int) ([]graph.Relation, string, error) {
	if limit < 1 || limit > graph.MaxEdgeRead {
		return nil, "", errors.New("edge limit must be 1..500")
	}

	edges, err := g.Edges(ctx, id, dir, label, since)
	if err != nil {
		return nil, "", err
	}

	start := 0
	if cursor != "" {
		if start, err = strconv.Atoi(cursor); err != nil {
			return nil, "", err
		}
	}

	*g.Pages++
	end := min(start+limit, len(edges))
	if end < len(edges) {
		return edges[start:end], strconv.Itoa(end), nil
	}

	return edges[start:end], "", nil
}

func BusyOWASP(n int) VendorGraph {
	g := VendorFixture()
	var nodes []graph.Relation
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("h%d.owasp.org", i)
		g.Assets[name] = graph.Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		nodes = append(nodes, graph.Relation{ID: "node-" + name, FromID: "owasp.org", ToID: name, Label: "node",
			Type: "SimpleRelation"})
	}
	g.Links = append(nodes, g.Links...)

	return g
}
