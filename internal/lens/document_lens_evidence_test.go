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

func docRel(subj, subjType, pred, obj, objType, sha string) graph.Evidence {
	return graphtest.SimpleProp(propDocStatement, `{"kind":"relation","subject":"`+subj+`","subject_type":"`+subjType+
		`","predicate":"`+pred+`","object":"`+obj+`","object_type":"`+objType+`","sha256":"`+sha+`"}`)
}

// The suppliers and products owasp.org's own documents name are its
// vendors, cited; a third party's supplier and its own organization are not.
func TestDocumentVendors(t *testing.T) {
	g := documentRelationFixture()
	g.EvidenceByID["f-report"] = append(g.EvidenceByID["f-report"],
		docRel("OWASP Foundation", "Organization", "supplied_by", "Acme Dining Services", "Organization", "v1"),
		docRel("Payroll", "Service", "supplied_by", "Example Funder", "Organization", "v1"),
		docRel("OWASP Foundation", "Organization", "uses_product", "Workday", "Product", "v1"),
		docRel("Utica University", "Organization", "supplied_by", "Other Caterer", "Organization", "v1"),
		docRel("OWASP Foundation", "Organization", "supplied_by", "OWASP Foundation", "Organization", "v1"),
	)
	g.EvidenceByID["f-catalog"] = append(g.EvidenceByID["f-catalog"],
		docRel("OWASP Foundation", "Organization", "uses_product", "Workday", "Product", "v2"))

	vendors, err := documentVendors(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{}, map[string]bool{"owasp foundation": true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]VendorUse{}
	for _, v := range vendors {
		got[v.Vendor] = v
		if v.Kind != KindDocument {
			t.Errorf("%s kind %q", v.Vendor, v.Kind)
		}
	}
	if len(got) != 3 {
		t.Fatalf("vendors %+v", vendors)
	}
	if v := got["Example Funder"]; v.VendorID != "funder" || v.Assets != 1 {
		t.Errorf("a stored supplier %+v: want it resolved exactly", v)
	}
	if v := got["Workday"]; v.Assets != 2 || len(v.Examples) != 2 || !strings.Contains(v.Examples[0], "uses_product") {
		t.Errorf("a product named by two documents %+v", v)
	}
	if v, ok := got["Acme Dining Services"]; !ok || v.VendorID != "" {
		t.Errorf("an unstored supplier %+v: want it listed as written", v)
	}
	if _, ok := got["Other Caterer"]; ok {
		t.Error("a third party's supplier was listed")
	}

	text := ThirdPartyAnswer(ThirdPartyReport{Root: g.Assets["owasp.org"], Footprint: 2,
		FootprintTypes: map[string]int{"FQDN": 2}, Vendors: vendors})
	if !strings.Contains(text, "Workday: 2 document(s)") || !strings.Contains(text, KindDocument) {
		t.Errorf("answer:\n%s", text)
	}
}

// A membership owasp.org's own documents state is an affiliation, weighted
// as a first-party document and corroborated by a second version; an
// ambiguous name gives nothing.
func TestDocumentAffiliations(t *testing.T) {
	g := documentRelationFixture()
	g.Assets["consortium"] = graph.Asset{ID: "consortium", Type: "Organization", Key: "NY Six Liberal Arts Consortium",
		Content: map[string]any{"name": "NY Six Liberal Arts Consortium"}}
	g.orgs["ny six liberal arts consortium"] = []string{"consortium"}
	for _, f := range []string{"f-report", "f-catalog"} {
		sha := map[string]string{"f-report": "v1", "f-catalog": "v2"}[f]
		g.EvidenceByID[f] = append(g.EvidenceByID[f],
			docRel("OWASP Foundation", "Organization", "member_of", "NY Six Liberal Arts Consortium", "Organization", sha),
			docRel("Acme Holdings", "Organization", "partner_of", "OWASP Foundation", "Organization", sha))
	}

	affs, err := documentAffiliations(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{}, []graph.Asset{g.Assets["owasp"]})
	if err != nil {
		t.Fatal(err)
	}
	// the fixture's report also states a partnership with Example Funder, in
	// one version only
	got := map[string]docAffiliation{}
	for _, a := range affs {
		got[a.org.ID] = a
	}
	if len(got) != 2 {
		t.Fatalf("affiliations %+v", affs)
	}
	if a := got["consortium"]; !near(a.weight, 0.25) || !strings.Contains(a.evidence, "member_of") {
		t.Errorf("membership %+v: want it corroborated by both versions", a)
	}
	if a := got["funder"]; !near(a.weight, 0.20) || !strings.Contains(a.evidence, "partner_of") {
		t.Errorf("partnership %+v: want one first-party version", a)
	}

	r, err := FindAffiliation(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Candidates {
		if c.ID == "consortium" {
			if c.Confidence != 25 || len(c.Signals) != 1 || !strings.Contains(c.Signals[0], "stated in its own documents") {
				t.Errorf("consortium %+v", c)
			}
			return
		}
	}
	t.Errorf("the documented membership is not an affiliation: %+v", r.Candidates)
}
