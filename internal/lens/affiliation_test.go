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

func TestFindAffiliation(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	// Partner Inc shares a phone with OWASP (both contact records use it).
	add("ph1", "Phone", map[string]any{"e164": "+13155551000"})
	add("partner", "Organization", map[string]any{"name": "Partner Inc"})
	add("cr-partner", "ContactRecord", nil)
	link("cr-owasp", "phone", "ph1")
	link("cr-partner", "phone", "ph1")
	link("cr-partner", "organization", "partner")

	r, err := FindAffiliation(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]AffiliatedOrg{}
	for _, c := range r.Candidates {
		got[c.Name] = c
	}

	// Partner Inc via the shared phone.
	p, ok := got["Partner Inc"]
	if !ok || p.Confidence != 70 {
		t.Errorf("partner = %+v (all: %+v)", p, r.Candidates)
	}
	if len(p.Signals) != 1 || !strings.Contains(p.Signals[0], "shared phone") ||
		!strings.Contains(p.Signals[0], "+13155551000") {
		t.Errorf("partner signals = %+v", p.Signals)
	}

	// Utica University via the person shared on both registrant contacts.
	h, ok := got["Utica University"]
	if !ok || h.Confidence != 65 {
		t.Errorf("utica = %+v", h)
	}
	if len(h.Signals) != 1 || !strings.Contains(h.Signals[0], "shared person") {
		t.Errorf("utica signals = %+v", h.Signals)
	}

	// Highest confidence first.
	if len(r.Candidates) < 2 || r.Candidates[0].Name != "Partner Inc" {
		t.Errorf("order = %+v", r.Candidates)
	}

	text := r.Text()
	for _, want := range []string{"Partner Inc (confidence 70%)", "shared phone", "Utica University (confidence 65%)"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestNoisyOr(t *testing.T) {
	if noisyOr(nil) != 0 {
		t.Error("no signals -> 0")
	}
	if noisyOr([]float64{0.7}) != 0.7 {
		t.Errorf("single = %v", noisyOr([]float64{0.7}))
	}
	// 1 - (1-0.7)(1-0.65) = 1 - 0.105 = 0.895
	if v := noisyOr([]float64{0.7, 0.65}); v < 0.894 || v > 0.896 {
		t.Errorf("combined = %v, want ~0.895", v)
	}
}
