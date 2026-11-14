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
	jhu, its, jhmi, comcast := org("o1", "johns hopkins university"), org("o2", "jhu its"),
		org("o3", "johns hopkins medicine"), org("o4", "comcast cable communications")

	r := ThirdPartyReport{Root: graph.Asset{ID: "f", Type: "FQDN", Content: map[string]any{"name": "jhu.edu"}},
		Vendors: []VendorUse{
			{Vendor: "johns hopkins university", VendorID: "o1", Kind: "DNS: IP addresses", Assets: 504},
			{Vendor: "the johns hopkins university", VendorID: "o9", Kind: "Network: services", Assets: 3},
			{Vendor: "jhu its", VendorID: "o2", Kind: "DNS: IP addresses", Assets: 2},
			{Vendor: "johns hopkins medicine", VendorID: "o3", Kind: "Network: services", Assets: 1},
			{Vendor: "jhmi.edu", Kind: "DNS: FQDNs", Assets: 5},
			{Vendor: "comcast cable communications", VendorID: "o4", Kind: "DNS: IP addresses", Assets: 6},
			{Vendor: "cloudflare.net", Kind: "DNS: FQDNs", Assets: 1},
		}}
	f := FamilyReport{Domain: "jhu.edu", Main: &jhu, Members: []FamilyMember{
		{Organization: jhu, Relation: FamilySame},
		{Organization: its, Relation: FamilyDepartment},
		{Organization: jhmi, Relation: FamilyAffiliate},
		{Organization: comcast, Relation: FamilyOther},
	}, RelatedDomains: []RelatedDomain{{Domain: "jhmi.edu", Names: 40, CIDR: "162.129.0.0/16"}}}

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
		"johns hopkins university,the johns hopkins university,jhu its" {
		t.Errorf("institution's own = %s", got)
	}
	if got := strings.Join(names(r.Affiliates), ","); got != "johns hopkins medicine,jhmi.edu" {
		t.Errorf("affiliates = %s", got)
	}

	text := familyLines(r)
	for _, want := range []string{"ties jhu.edu to johns hopkins university",
		"The institution's own: johns hopkins university (504 asset(s), DNS: IP addresses)",
		"Affiliated organizations and domains: johns hopkins medicine"} {
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
	g := graphtest.PagedVendorGraph{VendorGraph: graphtest.BusyColgate(graph.MaxEdgeRead + 100), Pages: &pages}

	r, err := SearchThirdParties(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate.edu"])
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
	g := graphtest.BusyColgate(graph.MaxEdgeRead + 100)
	pg := graphtest.PagedVendorGraph{VendorGraph: g, Pages: new(int)}
	root := g.Assets["colgate.edu"]

	r, err := SearchThirdPartiesWithin(context.Background(), pg, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, root,
		LensLimits{MaxAssets: 100})
	if err != nil {
		t.Fatal(err)
	}
	if r.Footprint != 100 || r.Reason != "controlled asset limit" {
		t.Errorf("footprint %d, reason %q; want 100 and the asset limit", r.Footprint, r.Reason)
	}
	if text := FormatVendorReport(r); !strings.Contains(text, "Raise -max-assets") {
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

	for _, l := range []LensLimits{{MaxAssets: -1}, {MaxAssets: LensMaxAssetsLimit + 1},
		{MaxReads: LensMaxReadsLimit + 1}} {
		if _, err := SearchThirdPartiesWithin(context.Background(), pg, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, root,
			l); err == nil {
			t.Errorf("limits %+v accepted", l)
		}
	}
}

func TestOwnLabel(t *testing.T) {
	words := map[string]bool{"northrop": true, "grumman": true}
	for _, c := range []struct {
		name string
		want bool
	}{
		{"GRUMMAN1", true},
		{"UK_NORTHROP", true},
		{"NORTHROP-GRUMMAN-NET", true},
		{"northrop", false},
		{"northrop grumman systems", false},
		{"AS22903", false},
		{"northrop.example", false},
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
	ngc, auto := org("o1", "northrop grumman corporation"), org("o2", "automattic")
	r := ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "GRUMMAN1", VendorID: "rec1", Kind: "DNS: IP addresses", Assets: 4},
		{Vendor: "UK_NORTHROP", VendorID: "rec2", Kind: "DNS: IP addresses", Assets: 1},
		{Vendor: "ngc.com", Kind: "DNS: FQDNs", Assets: 2},
		{Vendor: "AS22903", VendorID: "as", Kind: "Network: services", Assets: 1},
		{Vendor: "akamai technologies", VendorID: "o9", Kind: "DNS: IP addresses", Assets: 9},
	}}
	f := FamilyReport{Domain: "northgrum.com", Main: &ngc, Members: []FamilyMember{
		{Organization: ngc, Relation: FamilySame, ByName: true},
		{Organization: auto, Relation: FamilyAffiliate},
	}}

	applyFamily(&r, f)
	var own, vendors []string
	for _, v := range r.InstitutionOwn {
		own = append(own, v.Vendor)
	}
	for _, v := range r.Vendors {
		vendors = append(vendors, v.Vendor)
	}
	if got := strings.Join(own, ","); got != "GRUMMAN1,UK_NORTHROP,ngc.com" {
		t.Errorf("institution's own = %s", got)
	}
	if got := strings.Join(vendors, ","); got != "AS22903,akamai technologies" {
		t.Errorf("vendors = %s", got)
	}
	if !relatedDomain(f, "_spf.automattic.com") || familyDomain(f, "_spf.automattic.com") ||
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
	main := org("o1", "national grid usa service company")
	r := ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "national grid", VendorID: "o2", Kind: "Network: services", Assets: 1},
		{Vendor: "nationalgridus", VendorID: "o3", Kind: "DNS: IP addresses", Assets: 1},
		{Vendor: "salesforce", VendorID: "o4", Kind: "DNS: IP addresses", Assets: 2},
	}}
	f := FamilyReport{Domain: "nationalgridus.com", Main: &main,
		Members: []FamilyMember{{Organization: main, Relation: FamilySame, ByName: true}}}
	applyFamily(&r, f)
	if len(r.InstitutionOwn) != 2 || len(r.Vendors) != 1 || r.Vendors[0].Vendor != "salesforce" {
		t.Errorf("own %+v, vendors %+v", r.InstitutionOwn, r.Vendors)
	}

	mvcc := org("m", "suny - mohawk valley community college")
	r = ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "state university of new york", VendorID: "s", Kind: "DNS: FQDNs", Assets: 7},
	}}
	applyFamily(&r, FamilyReport{Domain: "mvcc.edu", Main: &mvcc,
		Members: []FamilyMember{{Organization: mvcc, Relation: FamilySame, ByName: true}}})
	if len(r.Affiliates) != 1 || len(r.Vendors) != 0 {
		t.Errorf("affiliates %+v, vendors %+v", r.Affiliates, r.Vendors)
	}
}

// A domain on a network the institution itself holds is its own; one on an
// affiliate's network is affiliated.
func TestApplyFamilyOwnRelatedDomains(t *testing.T) {
	main := graph.Asset{ID: "o1", Type: "Organization", Content: map[string]any{"name": "northrop grumman corp."}}
	r := ThirdPartyReport{Vendors: []VendorUse{
		{Vendor: "northgrum.com", Kind: "DNS: FQDNs", Assets: 1},
		{Vendor: "jhmi.edu", Kind: "DNS: FQDNs", Assets: 1},
		{Vendor: "customer.example", Kind: "DNS: FQDNs", Assets: 1},
	}}
	applyFamily(&r, FamilyReport{Domain: "ngc.com", Main: &main,
		Members: []FamilyMember{{Organization: main, Relation: FamilySame, ByName: true}},
		RelatedDomains: []RelatedDomain{{Domain: "northgrum.com", Own: true, OwnNetwork: true},
			{Domain: "jhmi.edu"}, {Domain: "customer.example", OwnNetwork: true}}})
	if len(r.InstitutionOwn) != 1 || r.InstitutionOwn[0].Vendor != "northgrum.com" ||
		len(r.Affiliates) != 1 || r.Affiliates[0].Vendor != "jhmi.edu" ||
		len(r.Hosted) != 1 || r.Hosted[0].Vendor != "customer.example" {
		t.Errorf("own %+v, affiliates %+v, hosted %+v", r.InstitutionOwn, r.Affiliates, r.Hosted)
	}
	if text := familyLines(r); !strings.Contains(text, "Domains hosted on the institution's networks") {
		t.Errorf("hosted domains not listed:\n%s", text)
	}
}
