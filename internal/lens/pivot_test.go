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

// pivotGraph builds a FakeGraph with a phone and an address, each reachable
// back to organizations, for the seed-pivot tests.
func pivotGraph() graphtest.FakeGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, to, label string) {
		g.Links = append(g.Links, graph.Relation{ID: "e" + from + to + label, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	add("phone1", "Phone", map[string]any{"e164": "+15551234567"})
	add("loc1", "StreetAddress", map[string]any{"address": "1 Campus Road"})
	add("org1", "Organization", map[string]any{"name": "Example University"})
	add("cr1", "ContactRecord", nil)

	// phone1 <- cr1 --organization--> org1, and cr1 --location--> loc1.
	link("cr1", "phone1", "phone")
	link("cr1", "loc1", "street_address")
	link("cr1", "org1", "organization")
	return g
}

func TestResolveSeedPivotPhoneReachesOrganization(t *testing.T) {
	g := pivotGraph()

	res, err := ResolveSeedPivot(context.Background(), g, nil, g.Assets["phone1"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if res.SeedType != "Phone" || res.SeedValue != "+15551234567" {
		t.Fatalf("seed = %q %q", res.SeedType, res.SeedValue)
	}
	if len(res.Organizations) != 1 || res.Organizations[0].ID != "org1" {
		t.Fatalf("organizations = %+v, want org1", res.Organizations)
	}
	if res.Organizations[0].Via != "contact_record" {
		t.Errorf("via = %q, want contact_record", res.Organizations[0].Via)
	}
}

func TestResolveSeedPivotPrefersPrincipalAddress(t *testing.T) {
	g := pivotGraph()
	// org1 also lists loc1 as its headquarters: the principal tie must win over
	// the weaker shared-contact-record tie.
	g.Links = append(g.Links, graph.Relation{ID: "ehq", FromID: "org1", ToID: "loc1", Label: "hq_address",
		Type: "SimpleRelation"})

	res, err := ResolveSeedPivot(context.Background(), g, nil, g.Assets["loc1"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Organizations) != 1 {
		t.Fatalf("organizations = %+v, want one", res.Organizations)
	}
	if o := res.Organizations[0]; o.Via != "address_edge" || !o.Principal {
		t.Errorf("tie = %+v, want principal address_edge", o)
	}
}

func TestResolveSeedPivotSharedAddressHeldForReview(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	g.Assets["agent"] = graph.Asset{ID: "agent", Type: "StreetAddress", Key: "agent",
		Content: map[string]any{"address": "1209 N Orange St"}}
	// More organizations than the shared-address threshold all claim the one
	// address as their registered location.
	for i := 0; i <= PivotSharedAddressOrgs; i++ {
		id := fmt.Sprintf("o%d", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "Organization", Key: id,
			Content: map[string]any{"name": id}}
		g.Links = append(g.Links, graph.Relation{ID: "el" + id, FromID: id, ToID: "agent",
			Label: "legal_address", Type: "SimpleRelation"})
	}

	res, err := ResolveSeedPivot(context.Background(), g, nil, g.Assets["agent"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SharedAddress {
		t.Errorf("a %d-organization address was not flagged as shared", PivotSharedAddressOrgs+1)
	}
	if len(res.Domains) != 0 {
		t.Errorf("a shared address seeded %d domains; it must be held for review", len(res.Domains))
	}
	if len(res.Organizations) == 0 {
		t.Error("a shared address should still list its organizations for review")
	}
}

func TestResolveSeedPivotRejectsUnsupportedSeed(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{
		"x": {ID: "x", Type: "FQDN", Key: "example.com", Content: map[string]any{"name": "example.com"}},
	}}

	if _, err := ResolveSeedPivot(context.Background(), g, nil, g.Assets["x"], LensLimits{}); err == nil {
		t.Error("an FQDN seed was accepted; only Phone and StreetAddress pivot")
	}
}

func TestPivotRankingPutsSeedableOrgsFirst(t *testing.T) {
	orgs := []PivotOrg{
		{ID: "a", Name: "Alpha", Domains: []string{"a.com"}},
		{ID: "b", Name: "Bravo", Domains: []string{"b1.com", "b2.com"}},
		{ID: "c", Name: "Charlie", Principal: true},
	}
	rankPivotOrgs(orgs)

	// Principal first, then more domains before fewer.
	if orgs[0].ID != "c" || orgs[1].ID != "b" || orgs[2].ID != "a" {
		t.Errorf("order = %s %s %s, want c b a", orgs[0].ID, orgs[1].ID, orgs[2].ID)
	}
}

func TestPivotUnionDeduplicatesDomains(t *testing.T) {
	orgs := []PivotOrg{
		{Domains: []string{"shared.com", "a.com"}},
		{Domains: []string{"shared.com", "b.com"}},
	}
	got := unionDomains(orgs)

	want := []string{"a.com", "b.com", "shared.com"}
	if len(got) != len(want) {
		t.Fatalf("union = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("union = %v, want %v", got, want)
		}
	}
}
