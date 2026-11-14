// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
)

func TestFindOrganizationFamily(t *testing.T) {
	g := aitest.FamilyGraph()
	r, err := lens.FindOrganizationFamily(context.Background(), g, g.Assets["jhu.edu"])
	if err != nil {
		t.Fatal(err)
	}

	// The ARIN record of the university holds the network most of its
	// names use, so it has the most ties.
	if r.Main == nil || r.Main.ID != "jhu-arin" {
		t.Fatalf("main = %+v", r.Main)
	}

	got := map[string]string{}
	for _, m := range r.Members {
		got[m.Organization.ID] = m.Relation
	}
	want := map[string]string{"jhu": lens.FamilySame, "jhu-arin": lens.FamilySame, "its": lens.FamilyDepartment,
		"jhmi": lens.FamilyAffiliate, "isp": lens.FamilyOther, "person": lens.FamilySame}
	for id, rel := range want {
		if got[id] != rel {
			t.Errorf("%s: relation %q, want %q (members %v)", id, got[id], rel, got)
		}
	}
	for _, id := range []string{"cloud", "other", "unspecified"} {
		if rel, ok := got[id]; ok {
			t.Errorf("%s should not be family, got %s", id, rel)
		}
	}

	dedicated := map[string]bool{}
	for _, n := range r.Networks {
		dedicated[n.CIDR] = n.Dedicated
	}
	if !dedicated["128.220.0.0/16"] || !dedicated["162.129.0.0/16"] || dedicated["52.0.0.0/8"] ||
		!dedicated["10.20.0.0/16"] || dedicated["50.128.0.0/9"] {
		t.Errorf("networks = %+v", r.Networks)
	}

	related := map[string]bool{}
	for _, d := range r.RelatedDomains {
		related[d.Domain] = true
	}
	if !related["jhmi.edu"] || !related["jhsph.edu"] || related["customer1.com"] {
		t.Errorf("related domains = %+v", r.RelatedDomains)
	}

	// Only name variants are proposed for merging: the person who shares
	// the address is reported, not merged.
	units, merges := FamilyProposals(r)
	if len(units) != 1 || units[0].AssetID != "its" {
		t.Errorf("department proposals = %+v", units)
	}
	if len(merges) != 1 || (merges[0].DuplicateID != "jhu" && merges[0].SurvivorID != "jhu") {
		t.Errorf("merge proposals = %+v", merges)
	}
	if r.Reads == 0 {
		t.Error("the report does not count its reads")
	}

	text := lens.FormatFamilyReport(r)
	for _, want := range []string{"Main organization: johns hopkins university", "Affiliates:",
		"provider", "jhsph.edu", "Other organizations on its assets", "not proposed for merging"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func familyOf(t *testing.T, g aitest.FakeGraph, domain string) (lens.FamilyReport, map[string]string, map[string]bool) {
	t.Helper()
	r, err := lens.FindOrganizationFamily(context.Background(), g, g.Assets[domain])
	if err != nil {
		t.Fatal(err)
	}

	rel := map[string]string{}
	for _, m := range r.Members {
		rel[m.Organization.ID] = m.Relation
	}
	dedicated := map[string]bool{}
	for _, n := range r.Networks {
		dedicated[n.CIDR] = n.Dedicated
	}
	return r, rel, dedicated
}

// A company registered northgrum.com, ngc.com and northropgrumman.com; its
// networks are held under a variant of its name and serve all three, so
// northgrum.com has a third of no network's names.
func TestFamilyNetworksServingSeveralBrandDomains(t *testing.T) {
	g := aitest.NewBrandGraph()
	g.Org("ngc", "northrop grumman corporation", "", "", "")
	g.Org("ngs", "northrop grumman systems corporation", "", "", "")
	g.Org("host", "bighost", "", "", "")
	g.Registers("ngc", "northgrum.com", "ngc.com", "northropgrumman.com")
	g.Network("nb-1", "10.1.0.0/16", "ngs")
	g.Network("nb-host", "10.9.0.0/16", "host")
	g.Serve("northgrum.com", "nb-1", "a", 6, 1)
	g.Serve("ngc.com", "nb-1", "b", 10, 2)
	g.Serve("northropgrumman.com", "nb-1", "c", 10, 3)
	g.Serve("northgrum.com", "nb-host", "h", 5, 9)
	g.Serve("customer.example", "nb-host", "x", 40, 8)

	r, rel, dedicated := familyOf(t, g.Graph, "northgrum.com")
	if !dedicated["10.1.0.0/16"] || dedicated["10.9.0.0/16"] {
		t.Errorf("networks = %+v", r.Networks)
	}
	if rel["ngs"] != lens.FamilySame || rel["ngc"] != lens.FamilySame {
		t.Errorf("members = %v", rel)
	}
	if _, ok := rel["host"]; ok {
		t.Errorf("the hosting provider is family: %v", rel)
	}
}

// automattic.com: the company named like the domain holds the network its
// names use, which serves its other brands' names more.
func TestFamilyOrganizationNamedLikeTheDomain(t *testing.T) {
	g := aitest.NewBrandGraph()
	g.Org("auto", "automattic", "automattic, inc.", "US-CA", "")
	g.Org("unrelated", "datapipe", "", "", "")
	g.Network("nb-a", "10.1.0.0/16", "auto")
	g.Network("nb-u", "10.2.0.0/16", "unrelated")
	g.Serve("automattic.com", "nb-a", "a", 6, 1)
	g.Serve("wordpress.com", "nb-a", "w", 30, 2)
	g.Serve("automattic.com", "nb-u", "u", 5, 3)
	g.Serve("other.example", "nb-u", "o", 30, 4)

	r, rel, dedicated := familyOf(t, g.Graph, "automattic.com")
	if r.Main == nil || r.Main.ID != "auto" || !dedicated["10.1.0.0/16"] || dedicated["10.2.0.0/16"] {
		t.Fatalf("main = %+v, networks = %+v", r.Main, r.Networks)
	}
	if _, ok := rel["unrelated"]; ok {
		t.Errorf("members = %v", rel)
	}
	related := map[string]bool{}
	for _, d := range r.RelatedDomains {
		related[d.Domain] = true
	}
	if !related["wordpress.com"] {
		t.Errorf("related domains = %+v", r.RelatedDomains)
	}
}

// nationalgridus.com: a platform vendor is named on more of the domain's
// certificates than the company is; the company is named like the domain,
// so it stays the main organization.
func TestFamilyCertificateVendorIsNotMain(t *testing.T) {
	g := aitest.NewBrandGraph()
	g.Org("ng", "national grid usa service company", "", "", "")
	g.Org("sf", "salesforce", "salesforce, inc.", "US-DE", "")
	g.FQDN("nationalgridus.com")
	for i := 0; i < 3; i++ {
		g.Cert(fmt.Sprintf("sf%d", i), fmt.Sprintf("portal%d.nationalgridus.com", i), "sf")
	}
	for i := 0; i < 2; i++ {
		g.Cert(fmt.Sprintf("ng%d", i), fmt.Sprintf("www%d.nationalgridus.com", i), "ng")
	}

	r, rel, _ := familyOf(t, g.Graph, "nationalgridus.com")
	if r.Main == nil || r.Main.ID != "ng" {
		t.Fatalf("main = %+v", r.Main)
	}
	if rel["sf"] != lens.FamilyOther {
		t.Errorf("members = %v", rel)
	}
}

// Utica College became Utica University: the same institution, reported but
// not merged. NASA's centers carry unit words: units, not the institution.
func TestFamilyRenameAndCenters(t *testing.T) {
	g := aitest.NewBrandGraph()
	g.Org("uu", "utica university", "", "", "")
	g.Org("uc", "utica college", "", "", "")
	g.FQDN("utica.edu")
	for i := 0; i < 3; i++ {
		g.Cert(fmt.Sprintf("u%d", i), fmt.Sprintf("www%d.utica.edu", i), "uu")
	}
	g.Cert("c0", "old.utica.edu", "uc")

	r, rel, _ := familyOf(t, g.Graph, "utica.edu")
	if r.Main == nil || r.Main.ID != "uu" || rel["uc"] != lens.FamilySame {
		t.Fatalf("main = %+v, members = %v", r.Main, rel)
	}
	if _, merges := FamilyProposals(r); len(merges) != 0 {
		t.Errorf("a rename was proposed for merging: %+v", merges)
	}

	n := aitest.NewBrandGraph()
	n.Org("nasa", "nasa", "", "", "")
	n.Org("ames", "nasa ames research center", "", "", "")
	n.Org("gsfc", "nasa goddard space flight center", "", "", "")
	n.FQDN("nasa.gov")
	for i := 0; i < 3; i++ {
		n.Cert(fmt.Sprintf("n%d", i), fmt.Sprintf("www%d.nasa.gov", i), "nasa")
	}
	n.Cert("a0", "ames.nasa.gov", "ames")
	n.Cert("g0", "gsfc.nasa.gov", "gsfc")

	_, rel, _ = familyOf(t, n.Graph, "nasa.gov")
	if rel["ames"] != lens.FamilyDepartment || rel["gsfc"] != lens.FamilyDepartment {
		t.Errorf("members = %v", rel)
	}
}

// automattic.com's names spread over the company's small networks, none
// serving enough of them alone: together they tie the company.
func TestFamilyNamedLikeAcrossSmallNetworks(t *testing.T) {
	g := aitest.NewBrandGraph()
	g.Org("auto", "automattic", "", "", "")
	for i := 1; i <= 3; i++ {
		block := fmt.Sprintf("nb-%d", i)
		g.Network(block, fmt.Sprintf("10.%d.0.0/24", i), "auto")
		g.Serve("automattic.com", block, fmt.Sprintf("n%d-", i), 2, i)
	}

	// One of the small networks also serves the company's other brand, which
	// it registered, and a customer's site, which it did not.
	g.Serve("wordpress.com", "nb-1", "w", 3, 7)
	g.Registers("auto", "wordpress.com")
	g.Serve("customer.example", "nb-2", "c", 3, 8)

	r, rel, _ := familyOf(t, g.Graph, "automattic.com")
	if r.Main == nil || r.Main.ID != "auto" || rel["auto"] != lens.FamilySame {
		t.Fatalf("main = %+v, members = %v", r.Main, rel)
	}
	got := map[string]lens.RelatedDomain{}
	for _, d := range r.RelatedDomains {
		got[d.Domain] = d
	}
	if d := got["wordpress.com"]; !d.Own || !d.OwnNetwork {
		t.Errorf("the company's registered brand: %+v", d)
	}
	if d := got["customer.example"]; d.Own || !d.OwnNetwork {
		t.Errorf("a hosted customer counted as the company's own: %+v", d)
	}
	if text := lens.FormatFamilyReport(r); !strings.Contains(text, "customer.example (3 names, 10.2.0.0/24, hosted on") {
		t.Errorf("report does not set the hosted domain apart:\n%s", text)
	}
}

// A unit stored under a shorter name is the department its longer name is;
// a network the institution holds is the family's however few of its
// stored names are the domain's.
func TestFamilyUnitVariantsAndMemberNetworks(t *testing.T) {
	g := aitest.NewBrandGraph()
	g.Org("nasa", "nasa", "", "", "")
	g.Org("njpl", "nasa jet propulsion laboratory", "", "", "")
	g.Org("jpl", "jet propulsion laboratory", "", "", "")
	g.FQDN("nasa.gov")
	for i := 0; i < 3; i++ {
		g.Cert(fmt.Sprintf("n%d", i), fmt.Sprintf("www%d.nasa.gov", i), "nasa")
	}
	g.Cert("nj", "jpl.nasa.gov", "njpl")
	g.Cert("j0", "a.jpl.nasa.gov", "jpl")
	g.Cert("j1", "b.jpl.nasa.gov", "jpl")
	// A NASA network mostly serving other names.
	g.Network("nb-shared", "10.5.0.0/16", "nasa")
	g.Serve("nasa.gov", "nb-shared", "s", 5, 5)
	g.Serve("science.example", "nb-shared", "x", 40, 6)

	_, rel, dedicated := familyOf(t, g.Graph, "nasa.gov")
	if rel["jpl"] != lens.FamilyDepartment || rel["njpl"] != lens.FamilyDepartment {
		t.Errorf("members = %v", rel)
	}
	if !dedicated["10.5.0.0/16"] {
		t.Error("the institution's own network is listed as a provider's")
	}
}

// A name that is the institution's followed by a unit is a department, and
// an institution whose own name ends in a unit noun is still itself.
func TestFamilyUnitsByName(t *testing.T) {
	g := aitest.NewBrandGraph()
	g.Org("ur", "university of rochester", "", "", "")
	g.Org("urmc", "university of rochester medical center", "", "", "")
	g.FQDN("rochester.edu")
	for i := 0; i < 3; i++ {
		g.Cert(fmt.Sprintf("u%d", i), fmt.Sprintf("www%d.rochester.edu", i), "ur")
	}
	g.Cert("m0", "med.rochester.edu", "urmc")

	_, rel, _ := familyOf(t, g.Graph, "rochester.edu")
	if rel["urmc"] != lens.FamilyDepartment {
		t.Errorf("members = %v", rel)
	}

	c := aitest.NewBrandGraph()
	c.Org("a", "memorial cancer center", "", "", "")
	c.Org("b", "memorial cancer center", "memorial cancer center, inc.", "", "")
	c.FQDN("mcc.example")
	for i := 0; i < 3; i++ {
		c.Cert(fmt.Sprintf("a%d", i), fmt.Sprintf("www%d.mcc.example", i), "a")
	}
	c.Cert("b0", "portal.mcc.example", "b")

	_, rel, _ = familyOf(t, c.Graph, "mcc.example")
	if rel["b"] != lens.FamilySame {
		t.Errorf("an institution named like a unit was split from itself: %v", rel)
	}
}

// The lens reads outward from the domain, so organizations that have
// nothing to do with it cost no reads, however many are stored.
func TestFamilyReadsDoNotGrowWithUnrelatedOrganizations(t *testing.T) {
	reads := func(unrelated int) int {
		g := aitest.NewBrandGraph()
		g.Org("acme", "acme widgets", "", "", "")
		g.Registers("acme", "acme.example")
		for i := 0; i < 3; i++ {
			g.Cert(fmt.Sprintf("a%d", i), fmt.Sprintf("www%d.acme.example", i), "acme")
		}
		for i := 0; i < unrelated; i++ {
			id := fmt.Sprintf("other%d", i)
			g.Org(id, fmt.Sprintf("other company %d", i), "", "", "")
			g.Registers(id, fmt.Sprintf("other%d.example", i))
			g.Cert("c-"+id, fmt.Sprintf("www.other%d.example", i), id)
		}

		r, rel, _ := familyOf(t, g.Graph, "acme.example")
		if r.Main == nil || r.Main.ID != "acme" || len(rel) != 1 {
			t.Fatalf("main = %+v, members = %v", r.Main, rel)
		}
		return r.Reads
	}

	if few, many := reads(10), reads(1000); few != many {
		t.Errorf("reads grew with unrelated organizations: %d with 10, %d with 1000", few, many)
	}
}
