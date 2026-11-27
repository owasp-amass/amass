// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// A domain with more direct subdomains than one read returns is listed in
// full, up to the inventory's name limit, when the graph pages.
func TestInventoryPagesBusyNames(t *testing.T) {
	n := graph.MaxEdgeRead + 100
	g := graphtest.BusyOWASP(n)
	root := g.Assets["owasp.org"]
	opts := AdaptiveOptions{MaxInventory: 1000}

	paged := graphtest.PagedVendorGraph{VendorGraph: g, Pages: new(int)}
	r, err := searchFQDNInventory(context.Background(), paged, graph.DefaultLimits(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Matches) < n || r.Truncated {
		t.Errorf("paged inventory listed %d names (truncated=%v, %s); want at least %d", len(r.Matches),
			r.Truncated, r.Reason, n)
	}

	r, err = searchFQDNInventory(context.Background(), g, graph.DefaultLimits(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Matches) > graph.MaxEdgeRead {
		t.Errorf("bounded inventory: %d names, truncated=%v; want one read's worth, reported partial",
			len(r.Matches), r.Truncated)
	}
}

// A typed relationship answer returns as many matches as were asked for,
// past the per-node limit meant for model context.
func TestTypedRelationReadsRequestedMatches(t *testing.T) {
	g := graphtest.BusyOWASP(100)
	paged := graphtest.PagedVendorGraph{VendorGraph: g, Pages: new(int)}
	intent := TypedRelationIntent{Goal: InvestigationGoal{Subject: PlanSubject{Type: "FQDN", Field: "name",
		Value: "owasp.org"}, TargetTypes: []string{"FQDN"}},
		Hops: []PlanHop{{Direction: "out", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"}}}
	limits := graph.DefaultLimits()

	r, err := searchTypedRelationIntent(context.Background(), paged, limits, g.Assets["owasp.org"], intent,
		AdaptiveOptions{MaxMatches: limits.MaxFind})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Matches) != limits.MaxFind || limits.MaxFind <= limits.MaxPerNode {
		t.Errorf("got %d matches with max %d (per-node limit %d)", len(r.Matches), limits.MaxFind,
			limits.MaxPerNode)
	}
}
