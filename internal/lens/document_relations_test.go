// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// docGraph resolves organizations, people and addresses by exact name, as the
// repositories do: a name two organizations share is ambiguous.
type docGraph struct {
	graphtest.VendorGraph
	orgs map[string][]string
}

func (g docGraph) ResolveOrganizations(_ context.Context, q graph.OrganizationQuery, _ int) (graph.OrganizationResolution,
	error) {
	res := graph.OrganizationResolution{Query: q, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	name := q.Name
	if name == "" {
		name = q.LegalName
	}
	for _, id := range g.orgs[strings.ToLower(name)] {
		res.Candidates = append(res.Candidates, graph.OrganizationCandidate{Asset: g.Assets[id]})
	}
	switch len(res.Candidates) {
	case 0:
	case 1:
		res.Status = "matched"
	default:
		res.Status = "ambiguous"
	}
	return res, nil
}

func (g docGraph) ResolveAsset(_ context.Context, s graph.AssetSelector, _ int) (graph.AssetResolution, error) {
	res := graph.AssetResolution{Query: s, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	for _, a := range g.Assets {
		if a.Type == s.Type && a.Key == s.Value {
			res.Candidates = append(res.Candidates, graph.OrganizationCandidate{Asset: a})
		}
	}
	if len(res.Candidates) == 1 {
		res.Status = "matched"
	}
	return res, nil
}

// documentRelationFixture publishes two documents on owasp.org stating its
// structure, funding and address, alongside findings that must give nothing:
// an ambiguous name, an unknown one, a link already stored, a predicate with
// no OAM relation and a finding that is not a relationship.
func documentRelationFixture() docGraph {
	g := docGraph{VendorGraph: graphtest.VendorFixture(), orgs: map[string][]string{}}
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	asset := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	org := func(id, name string) {
		asset(id, "Organization", name, map[string]any{"name": name})
		g.orgs[strings.ToLower(name)] = append(g.orgs[strings.ToLower(name)], id)
	}

	g.orgs["owasp foundation"] = []string{"owasp"}
	org("foundation", "OWASP Alumni Fund")
	org("funder", "Example Funder")
	org("acme-1", "Acme Holdings")
	org("acme-2", "Acme Holdings")
	org("bookstore", "OWASP Bookstore")
	link("owasp", "subsidiary", "bookstore")
	asset("addr", "StreetAddress", "100 Main Street, Utica, NY 13502", map[string]any{"address": "100 Main Street, Utica, NY 13502"})

	rel := func(subj, subjType, pred, obj, objType, sha string) graph.Evidence {
		return graphtest.SimpleProp(propDocStatement, `{"kind":"relation","subject":"`+subj+`","subject_type":"`+
			subjType+`","predicate":"`+pred+`","object":"`+obj+`","object_type":"`+objType+`","sha256":"`+sha+`"}`)
	}
	for _, d := range []struct{ url, file, sha string }{
		{"https://www.owasp.org/report.pdf", "f-report", "v1"},
		{"https://www.owasp.org/catalog.pdf", "f-catalog", "v2"},
	} {
		asset("u-"+d.file, "URL", d.url, map[string]any{"url": d.url})
		link("u-"+d.file, "domain", "www.owasp.org")
		asset(d.file, "File", d.url, map[string]any{"url": d.url, "type": "application/pdf"})
		link("u-"+d.file, "file", d.file)
		g.EvidenceByID[d.file] = []graph.Evidence{
			rel("OWASP  Alumni Fund", "Organization", "unit_of", "OWASP Foundation", "Organization", d.sha),
		}
	}
	g.EvidenceByID["f-report"] = append(g.EvidenceByID["f-report"],
		rel("OWASP Foundation", "Organization", "funded_by", "Example Funder", "Organization", "v1"),
		rel("OWASP Foundation", "Organization", "located_at", "100 Main Street, Utica, NY 13502", "StreetAddress", "v1"),
		rel("Acme Holdings", "Organization", "subsidiary_of", "OWASP Foundation", "Organization", "v1"),
		rel("Nowhere Institute", "Organization", "unit_of", "OWASP Foundation", "Organization", "v1"),
		rel("OWASP Bookstore", "Organization", "unit_of", "OWASP Foundation", "Organization", "v1"),
		rel("OWASP Foundation", "Organization", "partner_of", "Example Funder", "Organization", "v1"),
		graphtest.SimpleProp(propDocStatement, `{"kind":"asset","subject":"vpn.owasp.org","subject_type":"FQDN"}`),
	)
	return g
}

// The documents owasp.org publishes give a review proposal for each
// relationship they state between stored assets, weighted as first-party and,
// when two document versions agree, corroborated; nothing else gives one.
func TestFindDocumentRelations(t *testing.T) {
	g := documentRelationFixture()
	r, err := FindDocumentRelations(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != DocumentRelationKind {
		t.Fatalf("kind %q", r.Kind)
	}

	got := map[string]RelationCandidate{}
	for _, c := range r.Candidates {
		got[c.FromID+" "+c.Label+" "+c.ToID] = c
	}
	// three between stored assets, and the unstored unit of the publisher
	if len(got) != 4 {
		t.Fatalf("candidates %+v", r.Candidates)
	}
	if c := got["owasp org_unit "]; c.NewTo == nil || c.NewTo.Name != "Nowhere Institute" ||
		c.NewTo.Key != "OWASP Foundation / Nowhere Institute" {
		t.Errorf("new unit candidate %+v", c)
	}

	unit, ok := got["owasp org_unit foundation"]
	if !ok || unit.Confidence != 50 || len(unit.EvidenceIDs) != 2 || len(unit.Signals) != 2 {
		t.Fatalf("unit candidate %+v: want the parent first, corroborated by both documents", unit)
	}
	if !strings.Contains(unit.Signals[0], "unit of another") || !strings.Contains(strings.Join(unit.Signals, " "),
		"https://www.owasp.org/catalog.pdf") {
		t.Errorf("unit signals %v", unit.Signals)
	}
	if c, ok := got["owasp funding_source funder"]; !ok || c.Confidence != 40 || len(c.EvidenceIDs) != 1 {
		t.Errorf("funder candidate %+v: want one first-party document", c)
	}
	if _, ok := got["owasp street_address addr"]; !ok {
		t.Error("the stored address was not proposed")
	}
	if r.Candidates[0].FromID != "owasp" || r.Candidates[0].ToID != "foundation" {
		t.Errorf("the corroborated candidate is not first: %+v", r.Candidates[0])
	}
}

// A graph without exact lookups cannot attach document evidence safely.
func TestFindDocumentRelationsNeedsExactLookups(t *testing.T) {
	g := graphtest.VendorFixture()
	if _, err := FindDocumentRelations(context.Background(), g.FakeGraph, graphtest.VendorCatalog{
		PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"], LensLimits{}); err == nil {
		t.Error("ran without exact lookups")
	}
}

// Every document signal stays supporting: the bonuses never lift one past the
// cap, and the cap is below every strong signal.
func TestDocumentSignalCatalog(t *testing.T) {
	if len(DocumentSignals()) == 0 {
		t.Fatal("no document signals")
	}
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	for _, tc := range []struct {
		firstParty bool
		versions   int
		want       float64
	}{
		{false, 1, 0.15}, {true, 1, 0.20}, {false, 3, 0.20}, {true, 2, 0.25},
	} {
		if got := DocumentWeight(tc.firstParty, tc.versions, time.Time{}); !near(got, tc.want) {
			t.Errorf("DocumentWeight(%v, %d) = %.2f, want %.2f", tc.firstParty, tc.versions, got, tc.want)
		}
	}
	if w := DocumentSignalWeights(); w.Cap >= 0.35 {
		t.Errorf("cap %.2f reaches a strong signal", w.Cap)
	}
	if documentConfidence(DocumentWeight(true, 2, time.Time{})) != 50 ||
		documentConfidence(DocumentWeight(true, 1, time.Time{})) != 40 {
		t.Error("confidence is not twice the weight")
	}

	// a finding keeps its weight while current, then loses it in a straight
	// line to aged_factor at the stale age
	w := DocumentWeights{CurrentYears: 2, AgedFactor: 0.5}
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	year := 365 * 24 * time.Hour
	for _, tc := range []struct {
		age  time.Duration
		want float64
	}{{0, 1}, {2 * year, 1}, {7 * year / 2, 0.75}, {5 * year, 0.5}, {9 * year, 0.5}} {
		if got := documentFreshness(w, now.Add(-tc.age), now); !near(got, tc.want) {
			t.Errorf("freshness at %v = %.3f, want %.3f", tc.age, got, tc.want)
		}
	}
	if documentFreshness(w, time.Time{}, now) != 1 {
		t.Error("an undated document lost weight")
	}
	if validateDocumentSignals(documentSignalCatalog{Weights: DocumentWeights{Base: 0.15, Cap: 0.25,
		CurrentYears: 6, AgedFactor: 0.5}}) == nil {
		t.Error("a current age past the stale age was accepted")
	}

	bad := documentSignalCatalog{Weights: DocumentWeights{Base: 0.15, Cap: 0.4}}
	if validateDocumentSignals(bad) == nil {
		t.Error("a cap that reaches a strong signal was accepted")
	}
	bad = documentSignalCatalog{Weights: DocumentWeights{Base: 0.15, Cap: 0.25}, Signals: []DocumentSignal{{
		ID: "x", Title: "x", Rationale: "x", Guards: []string{"x"}, Predicates: []string{"unit_of"},
		SubjectType: "Organization", ObjectType: "Organization", Label: "subsidiary", Direction: "inverse"}}}
	if validateDocumentSignals(bad) == nil {
		t.Error("a label that contradicts the predicate catalog was accepted")
	}
}

// A unit the publisher's documents name with the publisher placeholder is
// proposed under the publisher: as a new unit when it is not stored, or is
// stored only as another organization's unit; never as a link to that other
// organization's office of the same name.
func TestFindDocumentRelationsPublisherUnits(t *testing.T) {
	g := documentRelationFixture()
	g.Assets["utica-counseling"] = graph.Asset{ID: "utica-counseling", Type: "Organization",
		Key: "Utica University / Counseling Center", Content: map[string]any{"name": "Counseling Center"}}
	g.orgs["counseling center"] = []string{"utica-counseling"}
	g.Links = append(g.Links, graph.Relation{ID: "hc", FromID: "utica", ToID: "utica-counseling",
		Label: "org_unit", Type: "SimpleRelation"})
	g.EvidenceByID["f-catalog"] = append(g.EvidenceByID["f-catalog"],
		graphtest.SimpleProp(propDocStatement, `{"kind":"relation","subject":"Counseling Center",`+
			`"subject_type":"Organization","predicate":"unit_of","object":"`+DocumentPublisher+`",`+
			`"object_type":"Organization","sha256":"v2"}`))

	r, err := FindDocumentRelations(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var unit *RelationCandidate
	for i, c := range r.Candidates {
		if c.ToID == "utica-counseling" {
			t.Fatalf("linked owasp to another college's office: %+v", c)
		}
		if c.NewTo != nil && c.NewTo.Name == "Counseling Center" {
			unit = &r.Candidates[i]
		}
	}
	if unit == nil || unit.FromID != "owasp" || unit.Label != "org_unit" ||
		unit.NewTo.Key != "OWASP Foundation / Counseling Center" {
		t.Fatalf("publisher unit %+v in %+v", unit, r.Candidates)
	}
	if !strings.Contains(strings.Join(unit.Signals, " "), "its publisher") {
		t.Errorf("signals %v do not say the unit is the publisher's", unit.Signals)
	}
}

func TestUnitKey(t *testing.T) {
	parent := graph.Asset{ID: "7", Key: "OWASP Foundation"}
	if got := UnitKey(parent, "  Counseling   Center "); got != "OWASP Foundation / Counseling Center" {
		t.Errorf("UnitKey = %q", got)
	}
}

// A finding the stored hierarchy or another finding contradicts gives no
// proposal: one that puts an organization over one stored above it, a unit
// already stored under an unrelated organization, and two organizations the
// documents each put over the other. (A unit of the publisher stored under
// another organization is proposed as a new unit instead: see
// TestFindDocumentRelationsPublisherUnits.)
func TestFindDocumentRelationsContradictions(t *testing.T) {
	g := documentRelationFixture()
	add := func(id, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Organization", Key: name, Content: map[string]any{"name": name}}
		g.orgs[strings.ToLower(name)] = []string{id}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	rel := func(file, subj, obj, sha string) {
		g.EvidenceByID[file] = append(g.EvidenceByID[file], graphtest.SimpleProp(propDocStatement,
			`{"kind":"relation","subject":"`+subj+`","subject_type":"Organization","predicate":"unit_of",`+
				`"object":"`+obj+`","object_type":"Organization","sha256":"`+sha+`"}`))
	}

	add("holding", "OWASP Holding")
	link("holding", "subsidiary", "owasp")
	rel("f-report", "OWASP Holding", "OWASP Foundation", "v1")

	add("other", "Utica Products")
	add("office", "Grants Office")
	link("other", "org_unit", "office")
	rel("f-report", "Grants Office", "OWASP Alumni Fund", "v1")

	add("lab", "OWASP Lab")
	rel("f-report", "OWASP Lab", "OWASP Alumni Fund", "v1")
	rel("f-catalog", "OWASP Alumni Fund", "OWASP Lab", "v2")

	r, err := FindDocumentRelations(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Candidates {
		for _, id := range []string{"holding", "office", "lab"} {
			if c.FromID == id || c.ToID == id {
				t.Errorf("a contradicted finding was proposed: %+v", c)
			}
		}
	}
	if len(r.Candidates) != 4 {
		t.Errorf("candidates %+v, want the fixture's four", r.Candidates)
	}
}
