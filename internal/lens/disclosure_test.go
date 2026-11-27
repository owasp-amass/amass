// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestParseExpires(t *testing.T) {
	for _, s := range []string{"2027-01-01T00:00:00Z", "2027-01-01T00:00:00.000Z", "2027-01-01"} {
		if _, ok := parseExpires(s); !ok {
			t.Errorf("parseExpires(%q) failed", s)
		}
	}
	if _, ok := parseExpires("whenever"); ok {
		t.Error("parseExpires accepted garbage")
	}
}

func TestFindDisclosure(t *testing.T) {
	disclosureNow = func() time.Time { return time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC) }
	defer func() { disclosureNow = time.Now }()

	g := graphtest.VendorFixture()
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: rt})
	}

	add("file", "URL", map[string]any{"url": "https://owasp.org/.well-known/security.txt", "host": "owasp.org",
		"path": "/.well-known/security.txt"})
	f0 := g.Assets["file"]
	f0.Key = "https://owasp.org/.well-known/security.txt"
	g.Assets["file"] = f0
	add("cr-sec", "ContactRecord", map[string]any{"discovered_at": "https://owasp.org/.well-known/security.txt"})
	add("id-sec", "Identifier", map[string]any{"id": "security@owasp.org", "id_type": "email"})
	add("url-policy", "URL", map[string]any{"url": "https://owasp.org/security-policy"})
	link("file", "domain", "owasp.org", "SimpleRelation")
	link("file", "contact", "cr-sec", "SimpleRelation")
	link("cr-sec", "id", "id-sec", "SimpleRelation")
	link("cr-sec", "url", "url-policy", "SimpleRelation")
	g.EvidenceByID["cr-sec-url-url-policy"] = []graph.Evidence{{Property: map[string]any{
		"property_name": "security_txt_field", "property_value": "policy"}}}
	// A security.txt that expired before the test clock.
	g.EvidenceByID["cr-sec"] = []graph.Evidence{{Property: map[string]any{
		"property_name": "security_txt_expires", "property_value": "2020-01-01T00:00:00Z"}}}

	r, err := FindDisclosure(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Files) != 1 {
		t.Fatalf("files = %+v", r.Files)
	}
	f := r.Files[0]
	if f.Host != "owasp.org" || !slices.Contains(f.Contacts, "security@owasp.org") || !f.Expired ||
		!slices.ContainsFunc(f.Links, func(s string) bool { return s == "policy: https://owasp.org/security-policy" }) {
		t.Errorf("file = %+v", f)
	}
	if !slices.ContainsFunc(r.Findings, func(d DisclosureFinding) bool { return d.Kind == DisclosureExpired }) {
		t.Errorf("findings = %+v", r.Findings)
	}
	if facts := r.Facts(); !slices.Contains(facts, "security.txt for owasp.org") ||
		!slices.Contains(facts, "expired owasp.org") {
		t.Errorf("facts = %v", facts)
	}
}
