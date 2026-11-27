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

// A domain with no documented owner lists the institution's own networks
// and its affiliates' domains as vendors; the family lens takes them out.
func TestApplyFamilySetsInstitutionApart(t *testing.T) {
	org := func(id, name string) graph.Asset {
		return graph.Asset{ID: id, Type: "Organization", Content: map[string]any{"name": name}}
	}
	uu, its, med, comcast := org("o1", "utica university"), org("o2", "utica its"),
		org("o3", "medicine at utica"), org("o4", "comcast cable communications")

	r := ThirdPartyReport{Root: graph.Asset{ID: "f", Type: "FQDN", Content: map[string]any{"name": "utica.edu"}},
		Vendors: []VendorUse{
			{Vendor: "utica university", VendorID: "o1", Kind: "DNS: IP addresses", Assets: 504},
			{Vendor: "the utica university", VendorID: "o9", Kind: "Network: services", Assets: 3},
			{Vendor: "utica its", VendorID: "o2", Kind: "DNS: IP addresses", Assets: 2},
			{Vendor: "medicine at utica", VendorID: "o3", Kind: "Network: services", Assets: 1},
			{Vendor: "medicineatutica.org", Kind: "DNS: FQDNs", Assets: 5},
			{Vendor: "comcast cable communications", VendorID: "o4", Kind: "DNS: IP addresses", Assets: 6},
			{Vendor: "cloudflare.net", Kind: "DNS: FQDNs", Assets: 1},
		}}
	f := FamilyReport{Domain: "utica.edu", Main: &uu, Members: []FamilyMember{
		{Organization: uu, Relation: FamilySame},
		{Organization: its, Relation: FamilyDepartment},
		{Organization: med, Relation: FamilyAffiliate},
		{Organization: comcast, Relation: FamilyOther},
	}, RelatedDomains: []RelatedDomain{{Domain: "medicineatutica.org", Names: 40, CIDR: "203.0.113.0/24"}}}

	applyFamily(&r, f)
	names := func(uses []VendorUse) []string {
		var out []string
		for _, u := range uses {
			out = append(out, u.Vendor)
		}
		return out
	}

	if got := strings.Join(names(r.Vendors), ","); got != "comcast cable communications,cloudflare.net" {
		t.Errorf("vendors = %s", got)
	}
	if got := strings.Join(names(r.InstitutionOwn), ","); got !=
		"utica university,the utica university,utica its" {
		t.Errorf("institution's own = %s", got)
	}
	if got := strings.Join(names(r.Affiliates), ","); got != "medicine at utica,medicineatutica.org" {
		t.Errorf("affiliates = %s", got)
	}

	text := familyLines(r)
	for _, want := range []string{"ties utica.edu to utica university",
		"The institution's own: utica university (504 asset(s), DNS: IP addresses)",
		"Affiliated organizations and domains: medicine at utica"} {
		if !strings.Contains(text, want) {
			t.Errorf("family lines lack %q:\n%s", want, text)
		}
	}
}

func TestApplyFamilyWithoutInstitution(t *testing.T) {
	r := ThirdPartyReport{Vendors: []VendorUse{{Vendor: "fastly", Kind: "DNS: IP addresses", Assets: 2}}}
	applyFamily(&r, FamilyReport{})
	if len(r.Vendors) != 1 || r.Institution != "" || familyLines(r) != "" {
		t.Errorf("a family without a main organization changed the report: %+v", r)
	}
}

// With paged reads, a label past one read is read in full.
func TestThirdPartyLensPagesBusyLabels(t *testing.T) {
	pages := 0
	g := graphtest.PagedVendorGraph{VendorGraph: graphtest.BusyOWASP(graph.MaxEdgeRead + 100), Pages: &pages}

	r, err := SearchThirdParties(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated {
		t.Errorf("paged read still partial: %s", r.Reason)
	}
	if got := r.FootprintTypes["FQDN"]; got < graph.MaxEdgeRead+100 {
		t.Errorf("footprint has %d FQDNs, want all %d subdomains", got, graph.MaxEdgeRead+100)
	}
	if pages == 0 {
		t.Error("the lens never paged")
	}
}

// A run's limits replace the defaults, and the report says which limit
// stopped it.
func TestThirdPartyLensLimits(t *testing.T) {
	g := graphtest.BusyOWASP(graph.MaxEdgeRead + 100)
	pg := graphtest.PagedVendorGraph{VendorGraph: g, Pages: new(int)}
	root := g.Assets["owasp.org"]

	r, err := SearchThirdPartiesWithin(context.Background(), pg, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, root,
		LensLimits{MaxAssets: 100})
	if err != nil {
		t.Fatal(err)
	}
	if r.Footprint != 100 || r.Reason != "controlled asset limit" {
		t.Errorf("footprint %d, reason %q; want 100 and the asset limit", r.Footprint, r.Reason)
	}
	if text := FormatVendorReport(r); !strings.Contains(text, "raise or drop -max-assets") {
		t.Errorf("report does not point at -max-assets:\n%s", text)
	}

	r, err = SearchThirdPartiesWithin(context.Background(), pg, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, root,
		LensLimits{MaxReads: 5})
	if err != nil {
		t.Fatal(err)
	}
	if r.Reason != "database read limit" {
		t.Errorf("reason %q, want the read limit", r.Reason)
	}

	for _, l := range []LensLimits{{MaxAssets: -1}, {MaxReads: -1}} {
		if _, err := SearchThirdPartiesWithin(context.Background(), pg, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, root,
			l); err == nil {
			t.Errorf("limits %+v accepted", l)
		}
	}
}

func TestOwnLabel(t *testing.T) {
	words := map[string]bool{"owasp": true, "foundation": true}
	for _, c := range []struct {
		name string
		want bool
	}{
		{"FOUNDATION1", true},
		{"UK_OWASP", true},
		{"OWASP-FOUNDATION-NET", true},
		{"owasp", false},
		{"owasp foundation systems", false},
		{"AS64501", false},
		{"owasp.example", false},
		{"AKAMAI-AS", false},
	} {
		if got := ownLabel(c.name, words); got != c.want {
			t.Errorf("ownLabel(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// Network labels carrying the institution's name and domains its name
// spells are its own; an SPF include in an affiliate's domain is related.
func TestApplyFamilyOwnLabelsAndDomains(t *testing.T) {
	org := func(id, name string) graph.Asset {
		return graph.Asset{ID: id, Type: "Organization", Content: map[string]any{"name": name}}
	}
	fdn, prod := org("o1", "owasp foundation"), org("o2", "utica products")
	r := ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "OWASP1", VendorID: "rec1", Kind: "DNS: IP addresses", Assets: 4},
		{Vendor: "UK_OWASP", VendorID: "rec2", Kind: "DNS: IP addresses", Assets: 1},
		{Vendor: "owasp.org", Kind: "DNS: FQDNs", Assets: 2},
		{Vendor: "AS64501", VendorID: "as", Kind: "Network: services", Assets: 1},
		{Vendor: "akamai technologies", VendorID: "o9", Kind: "DNS: IP addresses", Assets: 9},
	}}
	f := FamilyReport{Domain: "owaspfdn.org", Main: &fdn, Members: []FamilyMember{
		{Organization: fdn, Relation: FamilySame, ByName: true},
		{Organization: prod, Relation: FamilyAffiliate},
	}}

	applyFamily(&r, f)
	var own, vendors []string
	for _, v := range r.InstitutionOwn {
		own = append(own, v.Vendor)
	}
	for _, v := range r.Vendors {
		vendors = append(vendors, v.Vendor)
	}
	if got := strings.Join(own, ","); got != "OWASP1,UK_OWASP,owasp.org" {
		t.Errorf("institution's own = %s", got)
	}
	if got := strings.Join(vendors, ","); got != "AS64501,akamai technologies" {
		t.Errorf("vendors = %s", got)
	}
	if !relatedDomain(f, "_spf.uticaproducts.com") || familyDomain(f, "_spf.uticaproducts.com") ||
		relatedDomain(f, "spf.protection.outlook.com") {
		t.Error("SPF include classification is wrong")
	}
}

// Other names of the institution are its own; a system whose initials are a
// word of the institution's name is affiliated.
func TestApplyFamilyInstitutionNames(t *testing.T) {
	org := func(id, name string) graph.Asset {
		return graph.Asset{ID: id, Type: "Organization", Content: map[string]any{"name": name}}
	}
	main := org("o1", "utica products usa service company")
	r := ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "utica products", VendorID: "o2", Kind: "Network: services", Assets: 1},
		{Vendor: "uticaproductsus", VendorID: "o3", Kind: "DNS: IP addresses", Assets: 1},
		{Vendor: "salesforce", VendorID: "o4", Kind: "DNS: IP addresses", Assets: 2},
	}}
	f := FamilyReport{Domain: "uticaproductsus.com", Main: &main,
		Members: []FamilyMember{{Organization: main, Relation: FamilySame, ByName: true}}}
	applyFamily(&r, f)
	if len(r.InstitutionOwn) != 2 || len(r.Vendors) != 1 || r.Vendors[0].Vendor != "salesforce" {
		t.Errorf("own %+v, vendors %+v", r.InstitutionOwn, r.Vendors)
	}

	poly := org("m", "suny polytechnic institute")
	r = ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "state university of new york", VendorID: "s", Kind: "DNS: FQDNs", Assets: 7},
	}}
	applyFamily(&r, FamilyReport{Domain: "sunypoly.edu", Main: &poly,
		Members: []FamilyMember{{Organization: poly, Relation: FamilySame, ByName: true}}})
	if len(r.Affiliates) != 1 || len(r.Vendors) != 0 {
		t.Errorf("affiliates %+v, vendors %+v", r.Affiliates, r.Vendors)
	}
}

// A domain on a network the institution itself holds is its own; one on an
// affiliate's network is affiliated.
func TestApplyFamilyOwnRelatedDomains(t *testing.T) {
	main := graph.Asset{ID: "o1", Type: "Organization", Content: map[string]any{"name": "owasp foundation inc."}}
	r := ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "owaspfdn.org", Kind: "DNS: FQDNs", Assets: 1},
		{Vendor: "uticamedical.org", Kind: "DNS: FQDNs", Assets: 1},
		{Vendor: "customer.example", Kind: "DNS: FQDNs", Assets: 1},
	}}
	applyFamily(&r, FamilyReport{Domain: "owasp.org", Main: &main,
		Members: []FamilyMember{{Organization: main, Relation: FamilySame, ByName: true}},
		RelatedDomains: []RelatedDomain{{Domain: "owaspfdn.org", Own: true, OwnNetwork: true},
			{Domain: "uticamedical.org"}, {Domain: "customer.example", OwnNetwork: true}}})
	if len(r.InstitutionOwn) != 1 || r.InstitutionOwn[0].Vendor != "owaspfdn.org" ||
		len(r.Affiliates) != 1 || r.Affiliates[0].Vendor != "uticamedical.org" ||
		len(r.Hosted) != 1 || r.Hosted[0].Vendor != "customer.example" {
		t.Errorf("own %+v, affiliates %+v, hosted %+v", r.InstitutionOwn, r.Affiliates, r.Hosted)
	}
	if text := familyLines(r); !strings.Contains(text, "Domains hosted on the institution's networks") {
		t.Errorf("hosted domains not listed:\n%s", text)
	}
}
