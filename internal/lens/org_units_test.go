// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func orgUnitsGraph() graphtest.FakeGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	org := func(id, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Organization", Key: name + ":1",
			Content: map[string]any{"name": name}}
	}
	loc := func(id, addr, zip string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Location", Key: addr,
			Content: map[string]any{"address": addr, "postal_code": zip}}
	}
	at := func(o, l string) {
		g.Links = append(g.Links, graph.Relation{ID: "a" + o + l, FromID: o, ToID: l,
			Label: "hq_address", Type: "SimpleRelation"})
	}
	unitOf := func(parent, child string) {
		g.Links = append(g.Links, graph.Relation{ID: "u" + parent + child, FromID: parent, ToID: child,
			Label: "org_unit", Type: "SimpleRelation"})
	}

	// A system and a campus that share a postal address: name hierarchy
	// (acronym) + a strong shared link -> proposed.
	org("sys", "State University of New York")
	org("campus", "SUNY Polytechnic Institute")
	loc("loc1", "257 Fuller Rd, Albany NY", "12203")
	at("sys", "loc1")
	at("campus", "loc1")

	// Two unrelated organizations at the same address, no name hierarchy -> not
	// proposed (a shared address alone is not enough).
	org("alpha", "Alpha Corp")
	org("beta", "Beta Inc")
	loc("loc2", "1 Industrial Way, Rome NY", "13440")
	at("alpha", "loc2")
	at("beta", "loc2")

	// A parent/unit pair already linked by org_unit -> never re-proposed.
	org("globex", "Globex")
	org("globexlabs", "Globex Labs")
	loc("loc3", "5 Research Pkwy, Utica NY", "13502")
	at("globex", "loc3")
	at("globexlabs", "loc3")
	unitOf("globex", "globexlabs")

	return g
}

func TestFindOrgUnitsProposesSystemCampus(t *testing.T) {
	g := orgUnitsGraph()

	r, err := FindOrgUnits(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) != 1 {
		t.Fatalf("candidates = %+v, want exactly the sys->campus org_unit", r.Candidates)
	}

	c := r.Candidates[0]
	if c.FromID != "sys" || c.ToID != "campus" || c.Label != "org_unit" {
		t.Errorf("candidate = %s --%s--> %s, want sys --org_unit--> campus", c.FromID, c.Label, c.ToID)
	}
	if len(c.Signals) < 2 || len(c.Witness) != 2 || c.Confidence != orgUnitConfidence {
		t.Errorf("signals/witness/confidence not attached: %+v", c)
	}
}

func TestFindOrgUnitsRejectsNoHierarchyAndAlreadyLinked(t *testing.T) {
	g := orgUnitsGraph()
	r, _ := FindOrgUnits(context.Background(), g)

	for _, c := range r.Candidates {
		switch {
		case c.FromID == "alpha" || c.ToID == "alpha" || c.FromID == "beta" || c.ToID == "beta":
			t.Errorf("a shared address with no name hierarchy was proposed: %+v", c)
		case c.FromID == "globex" || c.ToID == "globex" || c.FromID == "globexlabs" || c.ToID == "globexlabs":
			t.Errorf("an already-linked org_unit pair was re-proposed: %+v", c)
		}
	}
}
