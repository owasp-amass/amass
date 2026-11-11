// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

// orgGraph builds organizations in the shapes the Colgate data showed.
type orgGraph struct {
	g    fakeGraph
	next int
}

func newOrgGraph() *orgGraph {
	return &orgGraph{g: fakeGraph{assets: map[string]Asset{}}}
}

func (o *orgGraph) id() string {
	o.next++
	return fmt.Sprintf("%d", o.next)
}

func (o *orgGraph) org(id, name, legal, jurisdiction, reg string) string {
	o.g.assets[id] = Asset{ID: id, Type: "Organization", Key: name + ":" + id, Content: map[string]any{
		"name": name, "legal_name": legal, "jurisdiction": jurisdiction, "registration_id": reg}}
	return id
}

func (o *orgGraph) link(from, to, label string) {
	o.g.links = append(o.g.links, Relation{ID: "e" + o.id(), FromID: from, ToID: to, Label: label})
}

func (o *orgGraph) ident(org, idtype, value string) {
	key := idtype + ":" + value
	if _, ok := o.g.assets[key]; !ok {
		o.g.assets[key] = Asset{ID: key, Type: "Identifier", Key: key,
			Content: map[string]any{"id": value, "id_type": idtype}}
	}
	o.link(org, key, "id")
}

// contact adds a contact record naming org, at location loc when given.
func (o *orgGraph) contact(org, cr, loc string) {
	if _, ok := o.g.assets[cr]; !ok {
		o.g.assets[cr] = Asset{ID: cr, Type: "ContactRecord", Key: cr}
	}
	o.link(cr, org, "organization")
	if loc != "" {
		if _, ok := o.g.assets[loc]; !ok {
			o.g.assets[loc] = Asset{ID: loc, Type: "Location", Key: loc}
		}
		o.link(cr, loc, "location")
	}
}

func findPair(r DuplicateReport, a, b string) *DuplicateCandidate {
	for i, c := range r.Candidates {
		if (c.Survivor.ID == a && c.Duplicate.ID == b) || (c.Survivor.ID == b && c.Duplicate.ID == a) {
			return &r.Candidates[i]
		}
	}

	return nil
}

func dupSignalIDs(c *DuplicateCandidate) []string {
	var out []string
	for _, s := range c.Signals {
		out = append(out, s.Signal)
	}

	return out
}

func TestFindDuplicateOrganizations(t *testing.T) {
	g := newOrgGraph()

	// GlobalSign: the same LEI and registration, recorded by two sources.
	g.org("2259", "globalsign", "globalsign", "BE", "0459134256")
	g.org("3585", "globalsign", "globalsign", "BE", "0459134256")
	for _, id := range []string{"2259", "3585"} {
		g.ident(id, "lei", "875500H0WKURA9XATD59")
		g.ident(id, "org_name", "GlobalSign")
	}
	g.contact("2259", "cr-gs", "loc-gs")

	// Amazon.com: a shared LEI, but recorded as parent and subsidiary.
	g.org("7516", "amazon.com", "amazon.com, inc.", "US-DE", "2620453")
	g.org("16825", "amazon.com", "amazon.com, inc.", "US-DE", "2620453")
	g.ident("7516", "lei", "ZXTILKJKG63JELOEG630")
	g.ident("16825", "lei", "ZXTILKJKG63JELOEG630")
	g.ident("16825", "org_name", "AMAZON.COM NV INVESTMENT HOLDINGS LLC")
	g.ident("7516", "arin", "AMAZO-4")
	g.contact("7516", "cr-amzn", "")
	g.link("7516", "16825", "subsidiary")

	// Google Trust Services: two spellings from certificates at one address.
	g.org("1673", "google trust services", "", "", "")
	g.org("1758", "google trust services", "", "", "")
	g.ident("1673", "org_name", "Google Trust Services")
	g.ident("1758", "org_name", "Google Trust Services LLC")
	g.contact("1673", "cr-gts1", "loc-gts")
	g.contact("1758", "cr-gts2", "loc-gts")

	// ISRG and its full name, at one address.
	g.org("2053", "isrg", "", "", "")
	g.org("2462", "internet security research group", "", "", "")
	g.contact("2053", "cr-isrg1", "loc-isrg")
	g.contact("2462", "cr-isrg2", "loc-isrg")

	// The same name in two jurisdictions: different companies.
	g.org("6466", "stripe", "stripe", "BE", "0888373015")
	g.org("9001", "stripe", "stripe, llc", "US-DE", "4675506")

	// An LEI attached by a bad enrichment match to an unrelated name.
	g.org("231", "apple", "apple 12", "FR", "532672227")
	g.org("9002", "pommes frites", "", "", "")
	g.ident("231", "lei", "969500RDBEVTUKOLE690")
	g.ident("9002", "lei", "969500RDBEVTUKOLE690")

	// One ARIN handle under two spellings.
	g.org("2565", "ithaka harbors", "", "", "")
	g.org("12527", "ithaka", "", "", "")
	g.ident("2565", "arin", "ITHAK")
	g.ident("12527", "arin", "ITHAK")

	// Privacy placeholders are never organizations to merge.
	g.org("4585", "registration private", "", "", "")
	g.org("4586", "registration private", "", "", "")

	r, err := FindDuplicateOrganizations(context.Background(), g.g)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, a, b, decision string
		has, lacks           []string
		survivor             string
	}{
		{name: "same LEI, registration and name", a: "2259", b: "3585", decision: GapPropose,
			has: []string{"shared_registry_identifier", "shared_registration", "same_brand_name"}, survivor: "2259"},
		{name: "parent and subsidiary sharing an LEI", a: "7516", b: "16825", decision: GapReview,
			has: []string{"shared_registry_identifier", "parent_or_subsidiary"}, survivor: "7516"},
		{name: "two spellings at one address", a: "1673", b: "1758", decision: GapReview,
			has: []string{"same_brand_name", "shared_location"}},
		{name: "initials at one address", a: "2053", b: "2462", decision: GapReview,
			has: []string{"name_abbreviation", "shared_location"}},
		{name: "same name, different jurisdictions", a: "6466", b: "9001", decision: GapWeak,
			has: []string{"same_brand_name", "jurisdiction_conflict"}},
		{name: "one ARIN handle", a: "2565", b: "12527", decision: GapReview,
			has: []string{"shared_network_handle"}},
	}
	for _, c := range cases {
		got := findPair(r, c.a, c.b)
		if got == nil {
			t.Errorf("%s: pair %s/%s not found", c.name, c.a, c.b)
			continue
		}
		if got.Decision != c.decision {
			t.Errorf("%s: decision %s, want %s (signals %v)", c.name, got.Decision, c.decision, dupSignalIDs(got))
		}
		for _, s := range c.has {
			if !slices.Contains(dupSignalIDs(got), s) {
				t.Errorf("%s: missing signal %s in %v", c.name, s, dupSignalIDs(got))
			}
		}
		if c.survivor != "" && got.Survivor.ID != c.survivor {
			t.Errorf("%s: survivor %s, want %s", c.name, got.Survivor.ID, c.survivor)
		}
	}

	// A shared LEI between unrelated names is an enrichment mistake.
	if got := findPair(r, "231", "9002"); got != nil {
		t.Errorf("unrelated names sharing an LEI: got %s with %v", got.Decision, dupSignalIDs(got))
	}
	if got := findPair(r, "4585", "4586"); got != nil {
		t.Errorf("placeholder organizations were compared: %v", dupSignalIDs(got))
	}
	for _, c := range r.Candidates {
		if c.Decision == GapPropose && slices.Contains(dupSignalIDs(&c), "jurisdiction_conflict") {
			t.Errorf("a jurisdiction conflict was proposed for merging: %s/%s", c.Survivor.ID, c.Duplicate.ID)
		}
	}
	if r.Candidates[0].Decision != GapPropose {
		t.Errorf("candidates are not ordered by decision: first is %s", r.Candidates[0].Decision)
	}
}

func TestBrandName(t *testing.T) {
	for in, want := range map[string]string{
		"GlobalSign nv-sa":                 "globalsign",
		"Google Trust Services LLC":        "google trust services",
		"Amazon.com, Inc.":                 "amazon.com",
		"Canva Pty Ltd":                    "canva",
		"DigiCert Inc":                     "digicert",
		"S.A.":                             "s.a",
		"Internet Security Research Group": "internet security research group",
	} {
		if got := brandName(in); got != want {
			t.Errorf("brandName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDuplicateCatalog(t *testing.T) {
	if len(DuplicateSignals()) == 0 {
		t.Fatal("empty duplicate catalog")
	}

	strongName := []OwnershipSignal{{ID: "x", Title: "x", Kind: "name", Strength: StrengthStrong, Weight: 0.5,
		Matcher: matchSameBrand, Params: SignalParams{LegalForms: []string{"inc"}}, Finds: "x", Rationale: "x"}}
	if validateDuplicateSignals(strongName) == nil {
		t.Error("a strong name signal was accepted")
	}

	negativeName := []OwnershipSignal{{ID: "x", Title: "x", Kind: "name", Strength: StrengthNegative, Weight: 0.5,
		Matcher: matchSameBrand, Params: SignalParams{LegalForms: []string{"inc"}}, Finds: "x", Rationale: "x"}}
	if validateDuplicateSignals(negativeName) == nil {
		t.Error("a negative non-conflict signal was accepted")
	}
}
