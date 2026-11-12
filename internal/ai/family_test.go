// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// familyGraph builds the shape the 11 Nov Johns Hopkins data had: the
// university on certificates and holding 128.220.0.0/16, its domain
// registered by the same institution under another name, JHMI holding a
// network that mostly serves jhu.edu, an IT department as a registration
// contact, a cloud provider hosting a few jhu.edu names among many others,
// and an unrelated organization with a similar name.
func familyGraph() fakeGraph {
	g := newOrgGraph()
	a := func(id, typ string, content map[string]any) {
		g.g.assets[id] = Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	fqdn := func(name string) { a(name, "FQDN", map[string]any{"name": name}) }
	resolve := func(name, ip, block string) {
		fqdn(name)
		if _, ok := g.g.assets[ip]; !ok {
			a(ip, "IPAddress", map[string]any{"address": ip})
		}
		g.g.links = append(g.g.links,
			Relation{ID: "e" + g.id(), FromID: name, ToID: ip, Label: "dns_record",
				Content: map[string]any{"header": map[string]any{"rr_type": 1}}},
			Relation{ID: "e" + g.id(), FromID: block, ToID: ip, Label: "contains"})
	}
	// network creates a netblock held through an ARIN record by org.
	network := func(block, cidr, org string) {
		a(block, "Netblock", map[string]any{"cidr": cidr})
		rec := "rec-" + block
		a(rec, "IPNetRecord", map[string]any{"cidr": cidr})
		g.link(block, rec, "registration")
		cr := "cr-" + block
		a(cr, "ContactRecord", nil)
		g.link(rec, cr, "registrant")
		g.link(cr, org, "organization")
	}

	g.org("jhu", "the johns hopkins university", "the johns hopkins university", "US-MD", "D00089169")
	g.org("jhu-arin", "johns hopkins university", "", "", "")
	g.org("jhmi", "the johns hopkins medical institutions", "", "", "")
	g.org("its", "hopkins information technology services", "", "", "")
	g.org("cloud", "cloudhost", "cloudhost, inc.", "US-WA", "1")
	g.org("other", "hopkins & sons plumbing", "", "", "")

	// Certificates name the university for jhu.edu names.
	for i := 0; i < 3; i++ {
		cert := fmt.Sprintf("cert%d", i)
		a(cert, "TLSCertificate", map[string]any{"subject_common_name": fmt.Sprintf("www%d.jhu.edu", i)})
		a("cr-"+cert, "ContactRecord", nil)
		g.link(cert, "cr-"+cert, "subject_contact")
		g.link("cr-"+cert, "jhu", "organization")
	}

	// The IT department is the domain's technical contact, with a jhu.edu
	// address.
	a("dr-jhu", "DomainRecord", map[string]any{"domain": "jhu.edu"})
	a("cr-its", "ContactRecord", nil)
	g.link("dr-jhu", "cr-its", "technical_contact")
	g.link("cr-its", "its", "organization")
	g.g.assets["email:hostmaster@jhu.edu"] = Asset{ID: "email:hostmaster@jhu.edu", Type: "Identifier",
		Key: "email:hostmaster@jhu.edu", Content: map[string]any{"id": "hostmaster@jhu.edu", "id_type": "email"}}
	g.link("cr-its", "email:hostmaster@jhu.edu", "id")

	// An ISP whose only stored addresses are the few jhu.edu names using it,
	// so its stored names look dedicated to jhu.edu.
	g.org("isp", "comcast cable communications", "", "", "")
	network("nb-isp", "50.128.0.0/9", "isp")
	for i := 0; i < 6; i++ {
		name := fmt.Sprintf("home%d.jhu.edu", i)
		resolve(name, fmt.Sprintf("50.128.0.%d", i), "nb-isp")
		g.link("jhu.edu", name, "node")
	}

	// A person named as the domain's registrant, sharing only the street
	// address; and a placeholder certificate subject.
	g.org("person", "eric torgersen", "", "", "")
	a("dr-reg", "DomainRecord", map[string]any{"domain": "jhu.edu"})
	a("cr-person", "ContactRecord", nil)
	g.link("dr-reg", "cr-person", "registrant_contact")
	g.link("cr-person", "person", "organization")
	a("loc-1", "Location", map[string]any{"address": "3400 north charles street baltimore md 21218"})
	a("loc-2", "Location", map[string]any{"address": "3400 n. charles st., garland hall, baltimore, md 21218-2683"})
	g.link("cr-person", "loc-1", "location")
	g.org("unspecified", "unspecified", "", "", "")
	a("cert-u", "TLSCertificate", map[string]any{"subject_common_name": "x.jhu.edu"})
	a("cr-cert-u", "ContactRecord", nil)
	g.link("cert-u", "cr-cert-u", "subject_contact")
	g.link("cr-cert-u", "unspecified", "organization")

	// A network the university holds, whose stored names are mostly other
	// domains' (as when an active probe stores addresses without names):
	// held by a directly tied organization, it is dedicated anyway.
	network("nb-campus", "10.20.0.0/16", "jhu")
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("lab%d.jhu.edu", i)
		resolve(name, fmt.Sprintf("10.20.0.%d", i), "nb-campus")
		g.link("jhu.edu", name, "node")
	}
	for i := 0; i < 30; i++ {
		resolve(fmt.Sprintf("guest%d.example%d.org", i, i), fmt.Sprintf("10.20.1.%d", i), "nb-campus")
	}

	network("nb-jhu", "128.220.0.0/16", "jhu-arin")
	g.link("cr-nb-jhu", "loc-2", "location")
	network("nb-jhmi", "162.129.0.0/16", "jhmi")
	network("nb-cloud", "52.0.0.0/8", "cloud")

	fqdn("jhu.edu")
	for i := 0; i < 22; i++ {
		name := fmt.Sprintf("h%d.jhu.edu", i)
		switch {
		case i < 10:
			resolve(name, fmt.Sprintf("128.220.0.%d", i), "nb-jhu")
		case i < 16:
			resolve(name, fmt.Sprintf("162.129.0.%d", i), "nb-jhmi")
		default:
			resolve(name, fmt.Sprintf("52.0.0.%d", i), "nb-cloud")
		}
		g.link("jhu.edu", name, "node")
	}
	// JHMI's network also serves jhmi.edu and jhsph.edu names; the cloud
	// network serves many unrelated customers.
	for i := 0; i < 4; i++ {
		resolve(fmt.Sprintf("m%d.jhmi.edu", i), fmt.Sprintf("162.129.1.%d", i), "nb-jhmi")
		resolve(fmt.Sprintf("p%d.jhsph.edu", i), fmt.Sprintf("162.129.2.%d", i), "nb-jhmi")
	}
	for i := 0; i < 40; i++ {
		resolve(fmt.Sprintf("site%d.customer%d.com", i, i), fmt.Sprintf("52.1.0.%d", i), "nb-cloud")
	}

	return g.g
}

func TestFindOrganizationFamily(t *testing.T) {
	g := familyGraph()
	r, err := FindOrganizationFamily(context.Background(), g, g.assets["jhu.edu"])
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
	want := map[string]string{"jhu": FamilySame, "jhu-arin": FamilySame, "its": FamilyDepartment,
		"jhmi": FamilyAffiliate, "isp": FamilyOther, "person": FamilySame}
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

	text := FormatFamilyReport(r)
	for _, want := range []string{"Main organization: johns hopkins university", "Affiliates:",
		"provider", "jhsph.edu", "Other organizations on its assets", "not proposed for merging"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestNameVariant(t *testing.T) {
	generic := loadFamilyRules().GenericWords
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"university at albany", "university at albany state university of new york", true},
		{"suny at albany", "university at albany state university of new york", true},
		{"johns hopkins university", "the johns hopkins university", true},
		{"the johns hopkins medical institutions", "the johns hopkins university", false},
		{"university at buffalo", "university at albany state university of new york", false},
		{"state university", "university at albany state university of new york", false},
	} {
		if got := nameVariant(c.a, c.b, generic); got != c.want {
			t.Errorf("nameVariant(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A company's family: its security unit (a registration contact) is a
// department; a vendor on a certificate with a unit word in its name is not;
// an organization sharing only generic words such as holdings or
// international is not an affiliate.
func TestFindOrganizationFamilyOfCompany(t *testing.T) {
	g := newOrgGraph()
	a := func(id, typ string, content map[string]any) {
		g.g.assets[id] = Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	cert := func(id, cn, org string) {
		a(id, "TLSCertificate", map[string]any{"subject_common_name": cn})
		a("cr-"+id, "ContactRecord", nil)
		g.link(id, "cr-"+id, "subject_contact")
		g.link("cr-"+id, org, "organization")
	}

	g.org("acme", "acme robotics holdings", "acme robotics holdings, inc.", "US-DE", "7")
	g.org("secops", "acme security operations", "", "", "")
	g.org("vendor", "global library services", "", "", "")
	g.org("generic", "holdings international ltd", "", "", "")

	a("acme.example", "FQDN", map[string]any{"name": "acme.example"})
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("www%d.acme.example", i)
		a(name, "FQDN", map[string]any{"name": name})
		g.link("acme.example", name, "node")
		cert(fmt.Sprintf("c%d", i), name, "acme")
	}
	cert("cv", "docs.acme.example", "vendor")
	cert("cg", "shop.acme.example", "generic")

	a("dr", "DomainRecord", map[string]any{"domain": "acme.example"})
	a("cr-sec", "ContactRecord", nil)
	g.link("dr", "cr-sec", "technical_contact")
	g.link("cr-sec", "secops", "organization")
	g.g.assets["email:soc@acme.example"] = Asset{ID: "email:soc@acme.example", Type: "Identifier",
		Key: "email:soc@acme.example", Content: map[string]any{"id": "soc@acme.example", "id_type": "email"}}
	g.link("cr-sec", "email:soc@acme.example", "id")

	r, err := FindOrganizationFamily(context.Background(), g.g, g.g.assets["acme.example"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Main == nil || r.Main.ID != "acme" {
		t.Fatalf("main = %+v", r.Main)
	}

	got := map[string]string{}
	for _, m := range r.Members {
		got[m.Organization.ID] = m.Relation
	}
	want := map[string]string{"acme": FamilySame, "secops": FamilyDepartment, "vendor": FamilyOther,
		"generic": FamilyOther}
	for id, rel := range want {
		if got[id] != rel {
			t.Errorf("%s: relation %q, want %q (members %v)", id, got[id], rel, got)
		}
	}
}
