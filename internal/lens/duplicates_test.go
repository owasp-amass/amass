// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

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
	g := graphtest.NewOrgGraph()

	// GlobalSign: the same LEI and registration, recorded by two sources.
	g.Org("2259", "globalsign", "globalsign", "BE", "0459134256")
	g.Org("3585", "globalsign", "globalsign", "BE", "0459134256")
	for _, id := range []string{"2259", "3585"} {
		g.Ident(id, "lei", "875500H0WKURA9XATD59")
		g.Ident(id, "org_name", "GlobalSign")
	}
	g.Contact("2259", "cr-gs", "loc-gs")

	// Amazon.com: a shared LEI, but recorded as parent and subsidiary.
	g.Org("7516", "amazon.com", "amazon.com, inc.", "US-DE", "2620453")
	g.Org("16825", "amazon.com", "amazon.com, inc.", "US-DE", "2620453")
	g.Ident("7516", "lei", "ZXTILKJKG63JELOEG630")
	g.Ident("16825", "lei", "ZXTILKJKG63JELOEG630")
	g.Ident("16825", "org_name", "AMAZON.COM NV INVESTMENT HOLDINGS LLC")
	g.Ident("7516", "arin", "AMAZO-4")
	g.Contact("7516", "cr-amzn", "")
	g.Link("7516", "16825", "subsidiary")

	// Google Trust Services: two spellings from certificates at one address.
	g.Org("1673", "google trust services", "", "", "")
	g.Org("1758", "google trust services", "", "", "")
	g.Ident("1673", "org_name", "Google Trust Services")
	g.Ident("1758", "org_name", "Google Trust Services LLC")
	g.Contact("1673", "cr-gts1", "loc-gts")
	g.Contact("1758", "cr-gts2", "loc-gts")

	// One organization from a certificate and from ARIN: only the name. (A
	// name shared with the ARIN pair below would join them into one group.)
	g.Org("7001", "hamilton harbors", "", "", "")
	g.Org("7002", "hamilton harbors", "", "", "")
	g.Ident("7002", "org_name", "Hamilton Harbors, Inc.")

	// ISRG and its full name, at one address.
	g.Org("2053", "isrg", "", "", "")
	g.Org("2462", "internet security research group", "", "", "")
	g.Contact("2053", "cr-isrg1", "loc-isrg")
	g.Contact("2462", "cr-isrg2", "loc-isrg")

	// The same name in two jurisdictions: different companies.
	g.Org("6466", "stripe", "stripe", "BE", "0888373015")
	g.Org("9001", "stripe", "stripe, llc", "US-DE", "4675506")

	// An LEI attached by a bad enrichment match to an unrelated name.
	g.Org("231", "apple", "apple 12", "FR", "532672227")
	g.Org("9002", "pommes frites", "", "", "")
	g.Ident("231", "lei", "969500RDBEVTUKOLE690")
	g.Ident("9002", "lei", "969500RDBEVTUKOLE690")

	// One ARIN handle under two spellings.
	g.Org("2565", "ithaka harbors", "", "", "")
	g.Org("12527", "ithaka", "", "", "")
	g.Ident("2565", "arin", "ITHAK")
	g.Ident("12527", "arin", "ITHAK")

	// A parent and subsidiary sharing a name and an address, with different
	// registrations and LEIs.
	g.Org("270", "google", "google llc", "US-DE", "3582691")
	g.Org("11437", "google international", "google international llc", "US-DE", "3525923")
	g.Ident("270", "lei", "7ZW8QJWVPR4P1J1KQY45")
	g.Ident("11437", "lei", "549300Y7W34DK0WBPY51")
	g.Ident("11437", "org_name", "Google")
	g.Contact("270", "cr-goog1", "loc-goog")
	g.Contact("11437", "cr-goog2", "loc-goog")
	g.Link("270", "11437", "subsidiary")

	// UAlbany as ARIN and WHOIS record it: two spellings of one street
	// address, and initials only in the department's name.
	g.Org("38172", "university at albany, state university of new york", "", "", "")
	g.Org("28909", "university at albany its", "", "", "")
	g.Graph.Assets["loc-ua1"] = graph.Asset{ID: "loc-ua1", Type: "Location", Key: "a1",
		Content: map[string]any{"address": "1400 washington ave room itb102 albany ny 12222 united states"}}
	g.Graph.Assets["loc-ua2"] = graph.Asset{ID: "loc-ua2", Type: "Location", Key: "a2",
		Content: map[string]any{"address": "1400 washington av, albany, ny 12222-1000, usa"}}
	g.Contact("38172", "cr-ua1", "loc-ua1")
	g.Contact("28909", "cr-ua2", "loc-ua2")
	g.Ident("38172", "org_name", "University at Albany ITS")

	// Two SEC filers recorded under the same Central Index Key and name,
	// as EDGAR and a certificate spell one company.
	g.Org("4110", "acme holdings", "acme holdings", "US-DE", "")
	g.Org("4111", "acme holdings", "acme holdings inc", "US-DE", "")
	g.Ident("4110", "sec cik", "0000012345")
	g.Ident("4111", "sec cik", "0000012345")
	g.Ident("4111", "org_name", "Acme Holdings")

	// Privacy placeholders are never organizations to merge.
	g.Org("4585", "registration private", "", "", "")
	g.Org("4586", "registration private", "", "", "")

	r, err := FindDuplicateOrganizations(context.Background(), g.Graph)
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
		{name: "only the same name, nothing against it", a: "7001", b: "7002", decision: GapReview,
			has: []string{"same_brand_name"}},
		{name: "same name, different jurisdictions", a: "6466", b: "9001", decision: GapWeak,
			has: []string{"same_brand_name", "jurisdiction_conflict"}},
		{name: "shared name and address against conflicting registrations", a: "270", b: "11437", decision: GapWeak,
			has: []string{"same_brand_name", "shared_location", "jurisdiction_conflict", "conflicting_registry_identifier"}},
		{name: "one street address spelled two ways", a: "38172", b: "28909", decision: GapReview,
			has: []string{"shared_location", "same_brand_name"}},
		{name: "one ARIN handle", a: "2565", b: "12527", decision: GapReview,
			has: []string{"shared_network_handle"}},
		{name: "same SEC CIK and name", a: "4110", b: "4111", decision: GapPropose,
			has: []string{"shared_registry_identifier", "same_brand_name"}, survivor: "4111"},
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

// docs/ai/DUPLICATES.md is generated from the duplicate catalog.
// Regenerate it with AMASS_UPDATE_SIGNALS_DOC=1 go test -run
// TestDuplicatesDocIsCurrent ./internal/ai/.
func TestDuplicatesDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "ai", "DUPLICATES.md")
	want := DuplicateSignalsMarkdown()
	if os.Getenv("AMASS_UPDATE_SIGNALS_DOC") != "" {
		if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Error("docs/ai/DUPLICATES.md is out of date; regenerate it with AMASS_UPDATE_SIGNALS_DOC=1 go test -run " +
			"TestDuplicatesDocIsCurrent ./internal/ai/")
	}
}

// One organization stored five times under one name gives four proposals
// into one survivor, not ten pairs.
func TestDuplicateGroupsHaveOneSurvivor(t *testing.T) {
	g := graphtest.NewOrgGraph()
	for i := 1; i <= 5; i++ {
		g.Org(fmt.Sprintf("%d", i), "national aeronautics and space administration", "", "", "")
	}
	// The third record has the most evidence.
	g.Contact("3", "cr-a", "")
	g.Contact("3", "cr-b", "")
	g.Org("9", "unrelated widgets", "", "", "")

	r, err := FindDuplicateOrganizations(context.Background(), g.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) != 4 {
		t.Fatalf("%d candidates, want 4: %+v", len(r.Candidates), r.Candidates)
	}
	dups := map[string]bool{}
	for _, c := range r.Candidates {
		if c.Survivor.ID != "3" || c.Group != 5 {
			t.Errorf("survivor %s, group %d; want 3 and 5", c.Survivor.ID, c.Group)
		}
		dups[c.Duplicate.ID] = true
	}
	if len(dups) != 4 || dups["3"] {
		t.Errorf("duplicates = %v", dups)
	}
	if text := FormatDuplicateReport(r); !strings.Contains(text, "one of 5 organizations") {
		t.Errorf("report does not name the group:\n%s", text)
	}
}

func unlimited() bool { return true }

func zeroTime() time.Time { return time.Time{} }

func TestReadEdgesPagesToTheEnd(t *testing.T) {
	ctx := context.Background()
	n := graph.MaxEdgeRead + 100
	paged := graphtest.PagedVendorGraph{VendorGraph: graphtest.BusyColgate(n), Pages: new(int)}
	all, _ := paged.Edges(ctx, "colgate.edu", "out", "node", zeroTime())

	edges, more, err := graph.ReadEdges(ctx, paged, "colgate.edu", "out", "node", LensMaxPerLabel, unlimited)
	if err != nil || len(edges) != len(all) || more {
		t.Errorf("paged read: %d edges, more=%v, err=%v; want all %d", len(edges), more, err, len(all))
	}

	edges, more, _ = graph.ReadEdges(ctx, paged, "colgate.edu", "out", "node", 550, unlimited)
	if len(edges) != 550 || !more {
		t.Errorf("capped read: %d edges, more=%v; want 550 and more", len(edges), more)
	}

	budget := 1
	spend := func() bool { budget--; return budget >= 0 }
	edges, more, _ = graph.ReadEdges(ctx, paged, "colgate.edu", "out", "node", LensMaxPerLabel, spend)
	if len(edges) != graph.MaxEdgeRead || !more {
		t.Errorf("budget of one read: %d edges, more=%v; want one page and more", len(edges), more)
	}

	// A graph that cannot page returns one bounded page and says so.
	edges, more, _ = graph.ReadEdges(ctx, graphtest.BusyColgate(n), "colgate.edu", "out", "node", LensMaxPerLabel, unlimited)
	if len(edges) != graph.MaxEdgeRead || !more {
		t.Errorf("bounded read: %d edges, more=%v; want one page and more", len(edges), more)
	}
}

// An organization named by more contact records than one read returns: the
// duplicate search reads them all when the graph pages, and says its
// result is partial when it cannot.
func TestDuplicateProfilesReadEveryContact(t *testing.T) {
	build := func() graphtest.VendorGraph {
		g := graphtest.VendorFixture()
		for i := 0; i < graph.MaxEdgeRead+50; i++ {
			cr := fmt.Sprintf("https://rdap.example/contact-%d", i)
			g.Assets[cr] = graph.Asset{ID: cr, Type: "ContactRecord", Key: cr}
			g.Links = append(g.Links, graph.Relation{ID: "org-" + cr, FromID: cr, ToID: "colgate", Label: "organization",
				Type: "SimpleRelation"})
		}
		return g
	}

	paged := &dupSearch{ctx: context.Background(), graph: graphtest.PagedVendorGraph{VendorGraph: build(), Pages: new(int)},
		profiles: map[string]*orgProfile{}}
	crs, err := paged.edges("colgate", "in", "organization")
	if err != nil || len(crs) < graph.MaxEdgeRead+50 || paged.report.Truncated {
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
