// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
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
	// The apex carries records with no address target (MX as a relation, TXT
	// and CAA as properties); all are record types the lens should report.
	g.EvidenceByID = map[string][]graph.Evidence{
		"owasp.org": {graphtest.TXTRecord("v=spf1 -all"), graphtest.CAARecord(`0 issue "letsencrypt.org"`)},
	}
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	r, err := FindSubdomains(context.Background(), g, catalog, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	names := subdomainsByName(r)
	if _, ok := names["owasp.org"]; !ok {
		t.Errorf("the root name is not listed: %v", r.Names)
	}
	if www := names["www.owasp.org"]; len(www.Addresses) != 1 || www.Addresses[0] != "151.101.1.1" ||
		www.Aliased || !slices.Equal(www.Records, []string{"A"}) {
		t.Errorf("www = %+v", www)
	}
	if portal := names["portal.owasp.org"]; len(portal.Addresses) != 1 || portal.Addresses[0] != "203.0.113.11" {
		t.Errorf("portal = %+v", portal)
	}
	// The apex's records come from a relation (MX) and from properties (TXT,
	// CAA), and it has no address of its own.
	if apex := names["owasp.org"]; !slices.Equal(apex.Records, []string{"CAA", "MX", "TXT"}) ||
		len(apex.Addresses) != 0 {
		t.Errorf("apex records = %+v", apex)
	}

	// Two names resolve to an address; the apex has records but no address.
	if r.Resolving != 2 {
		t.Errorf("resolving = %d, expected 2 (%+v)", r.Resolving, r.Names)
	}
	if r.WithRecords < 3 {
		t.Errorf("with_records = %d, expected at least 3 (%+v)", r.WithRecords, r.Names)
	}
	if len(r.Names) != r.WithRecords+r.DiscoveredOnly {
		t.Errorf("name classification does not add up: %d names, %d with records, %d discovered-only",
			len(r.Names), r.WithRecords, r.DiscoveredOnly)
	}

	if n := groupCount(r.ByAutonomousSystem, "AS64500 (OWASP-FOUNDATION)"); n != 1 {
		t.Errorf("AS64500 names = %d (%+v)", n, r.ByAutonomousSystem)
	}
	if n := groupCount(r.ByAutonomousSystem, "AS54113 (FASTLY)"); n != 1 {
		t.Errorf("AS54113 names = %d (%+v)", n, r.ByAutonomousSystem)
	}
	if len(r.ByAutonomousSystem) != 2 {
		t.Errorf("autonomous systems = %+v", r.ByAutonomousSystem)
	}
	if n := groupCount(r.ByNetblock, "203.0.113.0/24 (AS64500)"); n != 1 {
		t.Errorf("own netblock names = %d (%+v)", n, r.ByNetblock)
	}
	if n := groupCount(r.ByNetblock, "151.101.0.0/16 (AS54113)"); n != 1 {
		t.Errorf("cdn netblock names = %d (%+v)", n, r.ByNetblock)
	}

	text := r.Text()
	for _, want := range []string{"www.owasp.org [A] -> 151.101.1.1", "portal.owasp.org [A] -> 203.0.113.11",
		"owasp.org [CAA, MX, TXT]", "AS64500 (OWASP-FOUNDATION): 1 name(s)",
		"203.0.113.0/24 (AS64500): 1 name(s)"} {
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

	r, err := FindSubdomains(context.Background(), rangedGraph{g}, catalog, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	names := subdomainsByName(r)
	cdn := names["cdn.owasp.org"]
	if !cdn.Aliased || len(cdn.Addresses) != 2 || cdn.Addresses[0] != "13.32.1.1" ||
		len(cdn.Aliases) != 1 || cdn.Aliases[0] != "d1.cloudfront.net" {
		t.Errorf("aliased name = %+v", cdn)
	}
	if n := groupCount(r.ByAutonomousSystem, "AS16509 (AMAZON-02)"); n != 1 {
		t.Errorf("alias AS names = %d (%+v)", n, r.ByAutonomousSystem)
	}

	// mail.owasp.org's address has no stored netblock; its range puts it in
	// the university's own space, AS64500.
	if mail := names["mail.owasp.org"]; len(mail.Addresses) != 1 || mail.Addresses[0] != "203.0.113.99" {
		t.Errorf("mail = %+v", mail)
	}
	if n := groupCount(r.ByNetblock, "203.0.113.0/24 (AS64500)"); n < 1 {
		t.Errorf("names placed in the own netblock by range = %d (%+v)", n, r.ByNetblock)
	}
}

func TestFindSubdomainsLimits(t *testing.T) {
	g := graphtest.VendorFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}

	if _, err := FindSubdomains(context.Background(), g, nil, g.Assets["owasp.org"], LensLimits{}); err == nil {
		t.Error("the lens ran without relationship semantics")
	}
	if _, err := FindSubdomains(context.Background(), g, catalog, g.Assets["owasp.org"],
		LensLimits{MaxReads: -1}); err == nil {
		t.Error("a negative read limit was accepted")
	}

	r, err := FindSubdomains(context.Background(), g, catalog, g.Assets["owasp.org"], LensLimits{MaxReads: 3})
	if err != nil {
		t.Fatal(err)
	}
	if partial, _ := r.Partial(); !partial {
		t.Error("a tiny read budget did not mark the report partial")
	}
}
