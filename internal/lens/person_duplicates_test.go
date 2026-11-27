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

func personVariantGraph() graphtest.FakeGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	person := func(id, full, first, middle, family string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Person", Key: full, Content: map[string]any{
			"full_name": full, "first_name": first, "middle_name": middle, "family_name": family}}
	}
	g.Assets["acme"] = graph.Asset{ID: "acme", Type: "Organization", Key: "acme:1",
		Content: map[string]any{"name": "acme"}}
	member := func(person string) {
		g.Links = append(g.Links, graph.Relation{ID: "m" + person, FromID: "acme", ToID: person,
			Label: "member", Type: "SimpleRelation"})
	}

	// Two renderings of the same person, both members of Acme: a variant + a
	// shared organization.
	person("p1", "John A Smith", "John", "A", "Smith")
	person("p2", "John Smith", "John", "", "Smith")
	member("p1")
	member("p2")

	// Same name but no shared link: not proposed.
	person("p3", "John Smith Jones", "John", "", "Jones")
	person("p4", "Johnny Jones", "John", "", "Jones")

	// Same family, same first, both at Acme, but contradicting middle names:
	// different people.
	person("p5", "Mary B Doe", "Mary", "B", "Doe")
	person("p6", "Mary C Doe", "Mary", "C", "Doe")
	g.Assets["doeorg"] = graph.Asset{ID: "doeorg", Type: "Organization", Key: "doeorg:1",
		Content: map[string]any{"name": "doeco"}}
	g.Links = append(g.Links,
		graph.Relation{ID: "m5", FromID: "doeorg", ToID: "p5", Label: "member", Type: "SimpleRelation"},
		graph.Relation{ID: "m6", FromID: "doeorg", ToID: "p6", Label: "member", Type: "SimpleRelation"})
	return g
}

func TestFindPersonDuplicatesRequiresVariantAndSharedLink(t *testing.T) {
	g := personVariantGraph()

	report, err := FindPersonDuplicates(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 1 {
		t.Fatalf("candidates = %+v, want exactly the p1/p2 pair", report.Candidates)
	}

	c := report.Candidates[0]
	// The more complete record (the longer full name) survives.
	if c.SurvivorID != "p1" || c.DuplicateID != "p2" {
		t.Errorf("survivor/duplicate = %s/%s, want p1/p2", c.SurvivorID, c.DuplicateID)
	}
	if len(c.Signals) < 2 {
		t.Errorf("signals = %v, want a name and a link signal", c.Signals)
	}
}

func TestPersonDuplicatesRejectNoLinkAndBadMiddle(t *testing.T) {
	g := personVariantGraph()
	report, _ := FindPersonDuplicates(context.Background(), g)

	for _, c := range report.Candidates {
		pair := c.SurvivorID + "/" + c.DuplicateID
		if (c.SurvivorID == "p3" || c.DuplicateID == "p3") || (c.SurvivorID == "p4" || c.DuplicateID == "p4") {
			t.Errorf("a same-name pair with no shared link was proposed: %s", pair)
		}
		if c.SurvivorID == "p5" || c.DuplicateID == "p5" || c.SurvivorID == "p6" || c.DuplicateID == "p6" {
			t.Errorf("a pair with contradicting middle names was proposed: %s", pair)
		}
	}
}

func TestComparePersonsIsSeedScoped(t *testing.T) {
	g := personVariantGraph()

	// Seeding from p1 finds its duplicate p2.
	report, err := ComparePersons(context.Background(), g, []string{"p1"}, []string{"p2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 1 {
		t.Fatalf("seed-scoped candidates = %+v, want the p1/p2 pair", report.Candidates)
	}
}

// A name the person is known by counts: "Bob Smith" is not a rendering of
// "Robert Smith", but a record known as Robert Smith too is.
func TestPersonDuplicatesReadOtherNames(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}, EvidenceByID: map[string][]graph.Evidence{}}
	for id, first := range map[string]string{"bob": "Bob", "robert": "Robert"} {
		g.Assets[id] = graph.Asset{ID: id, Type: "Person", Key: first + " Smith", Content: map[string]any{
			"full_name": first + " Smith", "first_name": first, "family_name": "Smith"}}
		g.Links = append(g.Links, graph.Relation{ID: "m" + id, FromID: "acme", ToID: id, Label: "member",
			Type: "SimpleRelation"})
	}
	g.Assets["acme"] = graph.Asset{ID: "acme", Type: "Organization", Key: "acme:1",
		Content: map[string]any{"name": "acme"}}

	if report, err := FindPersonDuplicates(context.Background(), g); err != nil || len(report.Candidates) != 0 {
		t.Fatalf("without another name: %+v, %v", report.Candidates, err)
	}

	g.EvidenceByID["bob"] = []graph.Evidence{{ID: "t1", SubjectID: "bob", Kind: "property",
		Property: map[string]any{"property_name": graph.PersonAlias, "property_value": "Robert Smith"}}}
	report, err := FindPersonDuplicates(context.Background(), g)
	if err != nil || len(report.Candidates) != 1 {
		t.Fatalf("known as Robert Smith too: %+v, %v", report.Candidates, err)
	}
}

// A person known by another family name (a maiden name kept as another
// name) is compared with the people of that family name.
func TestPersonDuplicatesAcrossFamilyNames(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}, EvidenceByID: map[string][]graph.Evidence{}}
	for id, family := range map[string]string{"doe": "Doe", "smith": "Smith"} {
		g.Assets[id] = graph.Asset{ID: id, Type: "Person", Key: "Jane " + family, Content: map[string]any{
			"full_name": "Jane " + family, "first_name": "Jane", "family_name": family}}
		g.Links = append(g.Links, graph.Relation{ID: "m" + id, FromID: "acme", ToID: id, Label: "member",
			Type: "SimpleRelation"})
	}
	g.Assets["acme"] = graph.Asset{ID: "acme", Type: "Organization", Key: "acme:1",
		Content: map[string]any{"name": "acme"}}

	if report, err := FindPersonDuplicates(context.Background(), g); err != nil || len(report.Candidates) != 0 {
		t.Fatalf("different family names: %+v, %v", report.Candidates, err)
	}

	g.EvidenceByID["doe"] = []graph.Evidence{{ID: "t1", SubjectID: "doe", Kind: "property",
		Property: map[string]any{"property_name": graph.PersonAlias, "property_value": "Jane Smith"}}}
	report, err := FindPersonDuplicates(context.Background(), g)
	if err != nil || len(report.Candidates) != 1 {
		t.Fatalf("Jane Doe known as Jane Smith: %+v, %v", report.Candidates, err)
	}

	// the per-run comparison pairs them too, once
	report, err = ComparePersons(context.Background(), g, []string{"doe"}, []string{"smith", "smith"})
	if err != nil || len(report.Candidates) != 1 {
		t.Fatalf("seed-scoped: %+v, %v", report.Candidates, err)
	}
}
