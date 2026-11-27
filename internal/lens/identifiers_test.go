// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestFindIdentifiers(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, idType, value, status string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Identifier", Key: id,
			Content: map[string]any{"id_type": idType, "id": value, "status": status}}
	}
	link := func(from, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-id-" + to, FromID: from, ToID: to,
			Label: "id", Type: "SimpleRelation"})
	}

	add("id-lei", "lei", "5493001234567890ABCD", "ISSUED")
	add("id-ein", "ein", "13-1234567", "")
	add("id-ocid", "ocid", "us_ny/123456", "")
	link("owasp", "id-lei")
	link("owasp", "id-ein")
	link("owasp", "id-ocid")

	r, err := FindIdentifiers(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Identifiers) != 3 {
		t.Fatalf("identifiers = %+v", r.Identifiers)
	}
	byType := map[string]IdentifierEntry{}
	for _, e := range r.Identifiers {
		byType[e.Type] = e
	}
	lei, ok := byType["lei"]
	if !ok || lei.Value != "5493001234567890ABCD" || lei.Holder != "OWASP Foundation" || lei.Status != "ISSUED" {
		t.Errorf("lei entry = %+v", lei)
	}
	if _, ok := byType["ein"]; !ok {
		t.Errorf("ein not found: %+v", r.Identifiers)
	}
	if n := groupCount(r.ByType, "lei"); n != 1 {
		t.Errorf("lei count = %d (%+v)", n, r.ByType)
	}

	text := r.Text()
	for _, want := range []string{"LEI: 5493001234567890ABCD", "EIN: 13-1234567", "OWASP Foundation"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestFindIdentifiersBreach(t *testing.T) {
	g := graphtest.VendorFixture()
	g.Assets["id-email"] = graph.Asset{ID: "id-email", Type: "Identifier", Key: "id-email",
		Content: map[string]any{"id_type": "email", "id": "cio@owasp.org"}}
	g.Links = append(g.Links, graph.Relation{ID: "owasp-id-id-email", FromID: "owasp", ToID: "id-email",
		Label: "id", Type: "SimpleRelation"})

	adobe, _ := graph.EncodeBreach(graph.BreachInfo{Breach: "Adobe", Date: "2013",
		DataClasses: []string{"Email addresses", "Passwords"}, Source: "XposedOrNot", Verified: true})
	linkedin, _ := graph.EncodeBreach(graph.BreachInfo{Breach: "LinkedIn", Date: "2016", Source: "XposedOrNot"})
	g.EvidenceByID = map[string][]graph.Evidence{
		"id-email": {graphtest.SimpleProp("breach", adobe), graphtest.SimpleProp("breach", linkedin)},
	}

	r, err := FindIdentifiers(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if r.Exposed != 1 {
		t.Fatalf("exposed = %d (%+v)", r.Exposed, r.Identifiers)
	}
	var email IdentifierEntry
	for _, e := range r.Identifiers {
		if e.Value == "cio@owasp.org" {
			email = e
		}
	}
	if len(email.Breaches) != 2 {
		t.Errorf("email breaches = %+v", email)
	}
	if !strings.Contains(r.Text(), "breached: Adobe, LinkedIn") ||
		!strings.Contains(r.Text(), "appear in a known data breach") {
		t.Errorf("report lacks breach exposure:\n%s", r.Text())
	}
}

func TestFindIdentifiersEmpty(t *testing.T) {
	g := graphtest.VendorFixture()
	r, err := FindIdentifiers(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Identifiers) != 0 {
		t.Errorf("expected no identifiers, got %+v", r.Identifiers)
	}
	if !strings.Contains(r.Text(), "No registered identifier") {
		t.Errorf("unexpected text:\n%s", r.Text())
	}
}
