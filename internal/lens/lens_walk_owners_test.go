// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// ownerTestGraph stores two addresses in a netblock registered to Acme:
// address → netblock → registration record → registrant contact → Acme.
func ownerTestGraph() graphtest.FakeGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	add("ip1", "IPAddress", map[string]any{"address": "192.0.2.1"})
	add("ip2", "IPAddress", map[string]any{"address": "192.0.2.2"})
	add("nb", "Netblock", map[string]any{"cidr": "192.0.2.0/24"})
	add("rec", "IPNetRecord", map[string]any{"cidr": "192.0.2.0/24"})
	add("cr", "ContactRecord", map[string]any{"discovered_at": "rdap"})
	add("acme", "Organization", map[string]any{"name": "Acme"})
	link("nb", "contains", "ip1")
	link("nb", "contains", "ip2")
	link("nb", "registration", "rec")
	link("rec", "registrant", "cr")
	link("cr", "organization", "acme")
	return g
}

func newOwnerTestWalker(g graphtest.FakeGraph) *lensWalker {
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
	return newLensWalker(context.Background(), g, g, graph.MeaningsOf(catalog), catalog.Relations(), g.Assets["ip1"],
		&ThirdPartyReport{FootprintTypes: map[string]int{}})
}

// Controller searches started together advance a round at a time, each
// round read in one step read for every search.
func TestResolveControllersBatchesRounds(t *testing.T) {
	g := ownerTestGraph()
	w := newOwnerTestWalker(g)
	if err := w.resolveControllers([]graph.Asset{g.Assets["ip1"], g.Assets["ip2"]}, nil); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"ip1", "ip2"} {
		c, ok := w.controllers[id]
		if !ok {
			t.Fatalf("no controller cached for %s", id)
		}
		if len(c.orgs) != 1 || c.orgs[0].ID != "acme" {
			t.Errorf("%s controllers = %v, want acme", id, c.orgs)
		}
		if got := len(c.witness("acme", w.assets)); got != 4 {
			t.Errorf("%s witness has %d edges, want 4", id, got)
		}
	}
	// address, netblock, registration record, contact: one read each
	if w.report.Reads != 4 {
		t.Errorf("reads = %d, want 4", w.report.Reads)
	}
}

// A search reaching an owned asset stops there with own set, the owned
// asset last in its visited list.
func TestResolveControllersStopsAtOwned(t *testing.T) {
	g := ownerTestGraph()
	w := newOwnerTestWalker(g)
	c, err := w.controllerOf(g.Assets["ip1"], map[string]graph.Asset{"nb": g.Assets["nb"]})
	if err != nil {
		t.Fatal(err)
	}
	if !c.own || len(c.orgs) != 0 {
		t.Fatalf("own = %v, orgs = %v; want own and no organizations", c.own, c.orgs)
	}
	if last := c.visited[len(c.visited)-1]; last.ID != "nb" {
		t.Errorf("last visited = %s, want nb", last.ID)
	}
}

// The owner search finishes the round under way when its step budget runs
// out, and finds nothing further.
func TestResolveControllersStepBudget(t *testing.T) {
	g := ownerTestGraph()
	w := newOwnerTestWalker(g)
	w.ownerSteps = 2
	c, err := w.controllerOf(g.Assets["ip1"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.orgs) != 0 {
		t.Errorf("orgs = %v, want none within two steps", c.orgs)
	}
	if len(c.visited) != 2 {
		t.Errorf("visited %d assets, want 2", len(c.visited))
	}
	if !c.undetermined {
		t.Error("a search the step limit stopped with paths left is not marked undetermined")
	}
}

// A search that runs out of paths without an owner is conclusive: the asset
// has no documented owner.
func TestOwnerSearchWithoutPathsIsConclusive(t *testing.T) {
	g := ownerTestGraph()
	g.Assets["lone"] = graph.Asset{ID: "lone", Type: "FQDN", Key: "lone.example", Content: map[string]any{"name": "lone.example"}}
	w := newOwnerTestWalker(g)
	c, err := w.controllerOf(g.Assets["lone"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.undetermined || len(c.orgs) != 0 {
		t.Errorf("undetermined = %v, orgs = %v; want a conclusive search with no owner", c.undetermined, c.orgs)
	}

	found, err := w.controllerOf(g.Assets["ip1"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if found.undetermined {
		t.Error("a search that found its owner is marked undetermined")
	}
}

// owningOrganizations reads one step read a level.
func TestOwningOrganizationsByLevel(t *testing.T) {
	g := ownerTestGraph()
	w := newOwnerTestWalker(g)
	orgs, err := w.owningOrganizations(g.Assets["ip1"])
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 1 || orgs[0].ID != "acme" {
		t.Fatalf("owners = %v, want acme", orgs)
	}
	if w.report.Reads != 4 {
		t.Errorf("reads = %d, want 4", w.report.Reads)
	}
}

// A host's pages do not crowd out its registration: with more URLs on the
// host and on its domain than the owner steps allow, the registrant is still
// found, and no page is expanded on the way.
func TestOwnerSearchReachesRegistrationPastHostedURLs(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	add("example.edu", "FQDN", map[string]any{"name": "example.edu"})
	add("www.example.edu", "FQDN", map[string]any{"name": "www.example.edu"})
	add("dr", "DomainRecord", map[string]any{"domain": "example.edu"})
	add("cr", "ContactRecord", map[string]any{"discovered_at": "whois"})
	add("acme", "Organization", map[string]any{"name": "Example University"})
	link("example.edu", "node", "www.example.edu")
	link("example.edu", "registration", "dr")
	link("dr", "registrant_contact", "cr")
	link("cr", "organization", "acme")
	for _, host := range []string{"example.edu", "www.example.edu"} {
		for i := 0; i < 120; i++ {
			id := fmt.Sprintf("url-%s-%d", host, i)
			add(id, "URL", map[string]any{"url": fmt.Sprintf("https://%s/page%d", host, i), "host": host})
			link(id, "domain", host)
		}
	}

	w := newOwnerTestWalker(g)
	w.ownerSteps = 10
	c, err := w.controllerOf(g.Assets["www.example.edu"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.orgs) != 1 || c.orgs[0].ID != "acme" || c.undetermined {
		t.Fatalf("orgs = %v, undetermined = %v after visiting %d assets; want the registrant", c.orgs,
			c.undetermined, len(c.visited))
	}
	for _, v := range c.visited {
		if v.Type == "URL" {
			t.Errorf("a hosted URL (%s) was expanded before the registrant was found", v.ID)
		}
	}
}

func TestFanoutCost(t *testing.T) {
	for n, want := range map[int]int{0: 0, 1: 0, 2: 1, 3: 2, 4: 2, 5: 3, 300: 9, 65536: 16} {
		if got := fanoutCost(n); got != want {
			t.Errorf("fanoutCost(%d) = %d, want %d", n, got, want)
		}
	}
}
