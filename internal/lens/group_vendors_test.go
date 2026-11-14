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

func TestFindGroupVendors(t *testing.T) {
	g := graphtest.GroupVendorFixture()
	r, err := FindGroupVendors(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate"],
		LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Group.Members) != 3 || len(r.Scopes) != 3 {
		t.Fatalf("members %d, scopes %+v", len(r.Group.Members), r.Scopes)
	}

	used := map[string][]string{}
	for _, v := range r.Vendors {
		used[v.Vendor] = v.UsedBy
	}
	if got := used["EDUCAUSE"]; len(got) != 2 {
		t.Errorf("EDUCAUSE used by %v, want Colgate and Hamilton (vendors %v)", got, used)
	}
	if _, ok := used["cloudflare.com"]; !ok {
		t.Errorf("Hamilton's CDN missing: %v", used)
	}
	if r.Vendors[0].Vendor != "EDUCAUSE" {
		t.Errorf("the most widely used party is not first: %+v", r.Vendors[0])
	}

	internal := false
	for _, v := range r.Internal {
		if v.Vendor == "Colgate University" {
			internal = true
		}
	}
	if !internal {
		t.Errorf("a group organization was listed as an outside vendor: vendors %v, internal %+v", used, r.Internal)
	}

	text := FormatGroupVendorReport(r)
	for _, want := range []string{"Vendors across the corporate group of Colgate University",
		"EDUCAUSE: used by 2 of 3", "Services one group organization provides another"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// The read budget is shared across the group, and a group past it says so.
func TestFindGroupVendorsSharesTheReadBudget(t *testing.T) {
	g := graphtest.GroupVendorFixture()
	r, err := FindGroupVendors(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate"],
		LensLimits{MaxReads: groupVendorMinReads})
	if err != nil {
		t.Fatal(err)
	}
	if r.Reads > groupVendorMinReads+r.Group.Reads+graph.MaxEdgeRead {
		t.Errorf("read %d times with a budget of %d", r.Reads, groupVendorMinReads)
	}
	if !r.Truncated && len(r.Scopes) != 3 {
		t.Errorf("scopes %d without saying the result is partial", len(r.Scopes))
	}
}

// From a domain, its main organization and the domain are separate scopes,
// and an asset both reach is scanned once.
func TestFindGroupVendorsFromDomain(t *testing.T) {
	g := graphtest.GroupVendorFixture()
	r, err := FindGroupVendors(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate.edu"],
		LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Scopes) != 4 || r.Scopes[3].Name != "colgate.edu" {
		t.Fatalf("scopes = %+v", r.Scopes)
	}
	for _, v := range r.Vendors {
		if v.Vendor == "EDUCAUSE" && len(v.UsedBy) != 2 {
			t.Errorf("EDUCAUSE used by %v: the domain's scan repeated its organization's", v.UsedBy)
		}
	}
}
