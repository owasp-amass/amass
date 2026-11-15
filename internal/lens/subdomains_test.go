// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func subdomainsByName(r SubdomainsReport) map[string]SubdomainName {
	out := make(map[string]SubdomainName, len(r.Names))
	for _, n := range r.Names {
		out[n.Name] = n
	}

	return out
}

func groupCount(groups []ChangeGroup, key string) int {
	for _, g := range groups {
		if g.Key == key {
			return g.Count
		}
	}

	return -1
}

func TestFindSubdomains(t *testing.T) {
	g := graphtest.VendorFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	r, err := FindSubdomains(context.Background(), g, catalog, g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	names := subdomainsByName(r)
	if _, ok := names["colgate.edu"]; !ok {
		t.Errorf("the root name is not listed: %v", r.Names)
	}
	if www := names["www.colgate.edu"]; len(www.Addresses) != 1 || www.Addresses[0] != "151.101.1.1" || www.Aliased {
		t.Errorf("www = %+v", www)
	}
	if portal := names["portal.colgate.edu"]; len(portal.Addresses) != 1 || portal.Addresses[0] != "149.43.1.1" {
		t.Errorf("portal = %+v", portal)
	}

	// Only the two names with an address record resolve.
	if r.Resolved != 2 {
		t.Errorf("resolved = %d, expected 2 (%+v)", r.Resolved, r.Names)
	}

	if n := groupCount(r.ByAutonomousSystem, "AS1289 (COLGATE-UNIVERSITY)"); n != 1 {
		t.Errorf("AS1289 names = %d (%+v)", n, r.ByAutonomousSystem)
	}
	if n := groupCount(r.ByAutonomousSystem, "AS54113 (FASTLY)"); n != 1 {
		t.Errorf("AS54113 names = %d (%+v)", n, r.ByAutonomousSystem)
	}
	if len(r.ByAutonomousSystem) != 2 {
		t.Errorf("autonomous systems = %+v", r.ByAutonomousSystem)
	}
	if n := groupCount(r.ByNetblock, "149.43.0.0/16 (AS1289)"); n != 1 {
		t.Errorf("own netblock names = %d (%+v)", n, r.ByNetblock)
	}
	if n := groupCount(r.ByNetblock, "151.101.0.0/16 (AS54113)"); n != 1 {
		t.Errorf("cdn netblock names = %d (%+v)", n, r.ByNetblock)
	}

	text := r.Text()
	for _, want := range []string{"www.colgate.edu -> 151.101.1.1", "portal.colgate.edu -> 149.43.1.1",
		"AS1289 (COLGATE-UNIVERSITY): 1 name(s)", "149.43.0.0/16 (AS1289): 1 name(s)"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

// With range searches, an address stored under no netblock is placed in the
// netblock whose range holds it, and an alias is resolved to the addresses
// at the end of its chain.
func TestFindSubdomainsFollowsAliasesAndRanges(t *testing.T) {
	g := networkFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	r, err := FindSubdomains(context.Background(), rangedGraph{g}, catalog, g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	names := subdomainsByName(r)
	cdn := names["cdn.colgate.edu"]
	if !cdn.Aliased || len(cdn.Addresses) != 2 || cdn.Addresses[0] != "13.32.1.1" {
		t.Errorf("aliased name = %+v", cdn)
	}
	if n := groupCount(r.ByAutonomousSystem, "AS16509 (AMAZON-02)"); n != 1 {
		t.Errorf("alias AS names = %d (%+v)", n, r.ByAutonomousSystem)
	}

	// mail.colgate.edu's address has no stored netblock; its range puts it in
	// the university's own space, AS1289.
	if mail := names["mail.colgate.edu"]; len(mail.Addresses) != 1 || mail.Addresses[0] != "149.43.9.9" {
		t.Errorf("mail = %+v", mail)
	}
	if n := groupCount(r.ByNetblock, "149.43.0.0/16 (AS1289)"); n < 1 {
		t.Errorf("names placed in the own netblock by range = %d (%+v)", n, r.ByNetblock)
	}
}

func TestFindSubdomainsLimits(t *testing.T) {
	g := graphtest.VendorFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	if _, err := FindSubdomains(context.Background(), g, nil, g.Assets["colgate.edu"], LensLimits{}); err == nil {
		t.Error("the lens ran without relationship semantics")
	}
	if _, err := FindSubdomains(context.Background(), g, catalog, g.Assets["colgate.edu"],
		LensLimits{MaxReads: -1}); err == nil {
		t.Error("a negative read limit was accepted")
	}

	r, err := FindSubdomains(context.Background(), g, catalog, g.Assets["colgate.edu"], LensLimits{MaxReads: 3})
	if err != nil {
		t.Fatal(err)
	}
	if partial, _ := r.Partial(); !partial {
		t.Error("a tiny read budget did not mark the report partial")
	}
}
