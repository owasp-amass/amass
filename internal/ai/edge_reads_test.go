// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func unlimited() bool { return true }

func zeroTime() time.Time { return time.Time{} }

func TestReadEdgesPagesToTheEnd(t *testing.T) {
	ctx := context.Background()
	n := MaxEdgeRead + 100
	paged := pagedVendorGraph{vendorGraph: busyColgate(n), pages: new(int)}
	all, _ := paged.Edges(ctx, "colgate.edu", "out", "node", zeroTime())

	edges, more, err := readEdges(ctx, paged, "colgate.edu", "out", "node", lensMaxPerLabel, unlimited)
	if err != nil || len(edges) != len(all) || more {
		t.Errorf("paged read: %d edges, more=%v, err=%v; want all %d", len(edges), more, err, len(all))
	}

	edges, more, _ = readEdges(ctx, paged, "colgate.edu", "out", "node", 550, unlimited)
	if len(edges) != 550 || !more {
		t.Errorf("capped read: %d edges, more=%v; want 550 and more", len(edges), more)
	}

	budget := 1
	spend := func() bool { budget--; return budget >= 0 }
	edges, more, _ = readEdges(ctx, paged, "colgate.edu", "out", "node", lensMaxPerLabel, spend)
	if len(edges) != MaxEdgeRead || !more {
		t.Errorf("budget of one read: %d edges, more=%v; want one page and more", len(edges), more)
	}

	// A graph that cannot page returns one bounded page and says so.
	edges, more, _ = readEdges(ctx, busyColgate(n), "colgate.edu", "out", "node", lensMaxPerLabel, unlimited)
	if len(edges) != MaxEdgeRead || !more {
		t.Errorf("bounded read: %d edges, more=%v; want one page and more", len(edges), more)
	}
}

// An organization named by more contact records than one read returns: the
// duplicate search reads them all when the graph pages, and says its
// result is partial when it cannot.
func TestDuplicateProfilesReadEveryContact(t *testing.T) {
	build := func() vendorGraph {
		g := vendorFixture()
		for i := 0; i < MaxEdgeRead+50; i++ {
			cr := fmt.Sprintf("https://rdap.example/contact-%d", i)
			g.assets[cr] = Asset{ID: cr, Type: "ContactRecord", Key: cr}
			g.links = append(g.links, Relation{ID: "org-" + cr, FromID: cr, ToID: "colgate", Label: "organization",
				Type: "SimpleRelation"})
		}
		return g
	}

	paged := &dupSearch{ctx: context.Background(), graph: pagedVendorGraph{vendorGraph: build(), pages: new(int)},
		profiles: map[string]*orgProfile{}}
	crs, err := paged.edges("colgate", "in", "organization")
	if err != nil || len(crs) < MaxEdgeRead+50 || paged.report.Truncated {
		t.Errorf("paged: %d contact records, truncated=%v (%s), err=%v", len(crs), paged.report.Truncated,
			paged.report.Reason, err)
	}

	bounded := &dupSearch{ctx: context.Background(), graph: build(), profiles: map[string]*orgProfile{}}
	if _, err := bounded.edges("colgate", "in", "organization"); err != nil {
		t.Fatal(err)
	}
	if !bounded.report.Truncated || !strings.Contains(bounded.report.Reason, "in organization edges") {
		t.Errorf("a cut-short read was not reported: truncated=%v reason=%q", bounded.report.Truncated,
			bounded.report.Reason)
	}
}

// The re-check finds evidence past the first page, and never declares
// evidence gone without reading all of it.
func TestMissingWitnessReadsPastOnePage(t *testing.T) {
	n := MaxEdgeRead + 100
	last := fmt.Sprintf("h%d.colgate.edu", n-1)
	w := []WitnessEdge{{FromID: "colgate.edu", FromType: "FQDN", From: "colgate.edu", ToID: last, ToType: "FQDN",
		To: last, Label: "node"}}

	paged := pagedVendorGraph{vendorGraph: busyColgate(n), pages: new(int)}
	if missing, err := missingWitness(context.Background(), paged, w); err != nil || missing != "" {
		t.Errorf("evidence past the first page reported missing: %q, %v", missing, err)
	}

	gone := []WitnessEdge{{FromID: "colgate.edu", FromType: "FQDN", From: "colgate.edu", ToID: "gone.colgate.edu",
		ToType: "FQDN", To: "gone.colgate.edu", Label: "node"}}
	if missing, _ := missingWitness(context.Background(), paged, gone); missing == "" {
		t.Error("evidence absent from every page was not reported missing")
	}

	// Without paging the evidence cannot be confirmed either way, so it
	// counts as present.
	if missing, _ := missingWitness(context.Background(), busyColgate(n), gone); missing != "" {
		t.Errorf("unread evidence was declared gone: %q", missing)
	}
}
