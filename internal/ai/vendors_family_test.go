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

// A domain with no documented owner lists the institution's own networks
// and its affiliates' domains as vendors; the family lens takes them out.
func TestApplyFamilySetsInstitutionApart(t *testing.T) {
	org := func(id, name string) Asset {
		return Asset{ID: id, Type: "Organization", Content: map[string]any{"name": name}}
	}
	jhu, its, jhmi, comcast := org("o1", "johns hopkins university"), org("o2", "jhu its"),
		org("o3", "johns hopkins medicine"), org("o4", "comcast cable communications")

	r := ThirdPartyReport{Root: Asset{ID: "f", Type: "FQDN", Content: map[string]any{"name": "jhu.edu"}},
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

// A domain with more subdomains than one read returns still shows the
// vendors its other relationships name, and the report names the label
// that stayed partial.
func TestThirdPartyLensReadsBusyAssetsByLabel(t *testing.T) {
	g := vendorFixture()
	var nodes []Relation
	for i := 0; i < MaxEdgeRead+100; i++ {
		name := fmt.Sprintf("h%d.colgate.edu", i)
		g.assets[name] = Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		nodes = append(nodes, Relation{ID: "node-" + name, FromID: "colgate.edu", ToID: name, Label: "node",
			Type: "SimpleRelation"})
	}
	// The fake reader returns edges in stored order, so the subdomains fill
	// the first read.
	g.links = append(nodes, g.links...)

	r, err := searchThirdParties(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}
	if got := vendorNames(&r)["pphosted.com"]; got != "DNS: FQDNs" {
		t.Errorf("mail provider behind the busy domain missing: %v", vendorNames(&r))
	}
	if !r.Truncated || !strings.Contains(r.Reason, "out node edges on FQDN colgate.edu") {
		t.Errorf("reason %q does not name the partial label", r.Reason)
	}
}
