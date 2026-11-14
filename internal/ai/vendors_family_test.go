// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
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

// pagedVendorGraph adds paged edge reads to the vendor fixture; the cursor
// is the offset of the next edge in stored order.
type pagedVendorGraph struct {
	vendorGraph
	pages *int
}

func (g pagedVendorGraph) EdgesPage(ctx context.Context, id, dir, label string, since time.Time, cursor string,
	limit int) ([]Relation, string, error) {
	if limit < 1 || limit > MaxEdgeRead {
		return nil, "", errors.New("edge limit must be 1..500")
	}

	edges, err := g.Edges(ctx, id, dir, label, since)
	if err != nil {
		return nil, "", err
	}

	start := 0
	if cursor != "" {
		if start, err = strconv.Atoi(cursor); err != nil {
			return nil, "", err
		}
	}

	*g.pages++
	end := min(start+limit, len(edges))
	if end < len(edges) {
		return edges[start:end], strconv.Itoa(end), nil
	}

	return edges[start:end], "", nil
}

func busyColgate(n int) vendorGraph {
	g := vendorFixture()
	var nodes []Relation
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("h%d.colgate.edu", i)
		g.assets[name] = Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		nodes = append(nodes, Relation{ID: "node-" + name, FromID: "colgate.edu", ToID: name, Label: "node",
			Type: "SimpleRelation"})
	}
	g.links = append(nodes, g.links...)

	return g
}

// With paged reads, a label past one read is read in full.
func TestThirdPartyLensPagesBusyLabels(t *testing.T) {
	pages := 0
	g := pagedVendorGraph{vendorGraph: busyColgate(MaxEdgeRead + 100), pages: &pages}

	r, err := searchThirdParties(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated {
		t.Errorf("paged read still partial: %s", r.Reason)
	}
	if got := r.FootprintTypes["FQDN"]; got < MaxEdgeRead+100 {
		t.Errorf("footprint has %d FQDNs, want all %d subdomains", got, MaxEdgeRead+100)
	}
	if pages == 0 {
		t.Error("the lens never paged")
	}
}

// Paging stops at lensMaxPerLabel, and the report says so.
func TestThirdPartyLensCapsPagedLabels(t *testing.T) {
	defer func(n int) { lensMaxPerLabel = n }(lensMaxPerLabel)
	lensMaxPerLabel = 550

	pages := 0
	g := pagedVendorGraph{vendorGraph: busyColgate(MaxEdgeRead + 100), pages: &pages}
	r, err := searchThirdParties(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || !strings.Contains(r.Reason, "more than 550 out node edges on FQDN colgate.edu") {
		t.Errorf("reason %q does not name the capped label", r.Reason)
	}
	if got := vendorNames(&r)["pphosted.com"]; got != "DNS: FQDNs" {
		t.Errorf("vendor behind the capped label missing: %v", vendorNames(&r))
	}
}

// A run's limits replace the defaults, and the report says which limit
// stopped it.
func TestThirdPartyLensLimits(t *testing.T) {
	g := busyColgate(MaxEdgeRead + 100)
	pg := pagedVendorGraph{vendorGraph: g, pages: new(int)}
	root := g.assets["colgate.edu"]

	r, err := searchThirdPartiesWithin(context.Background(), pg, vendorCatalog{testOAMCatalog}, root,
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

	r, err = searchThirdPartiesWithin(context.Background(), pg, vendorCatalog{testOAMCatalog}, root,
		LensLimits{MaxReads: 5})
	if err != nil {
		t.Fatal(err)
	}
	if r.Reason != "database read limit" {
		t.Errorf("reason %q, want the read limit", r.Reason)
	}

	for _, l := range []LensLimits{{MaxAssets: -1}, {MaxAssets: LensMaxAssetsLimit + 1},
		{MaxReads: LensMaxReadsLimit + 1}} {
		if _, err := searchThirdPartiesWithin(context.Background(), pg, vendorCatalog{testOAMCatalog}, root,
			l); err == nil {
			t.Errorf("limits %+v accepted", l)
		}
	}
}

// URLs are followed after every other controlled asset, so a run that
// reaches its asset limit spends it on names and networks first.
func TestFootprintFollowsURLsLast(t *testing.T) {
	base := vendorFixture()
	want, err := searchThirdParties(context.Background(), base, vendorCatalog{testOAMCatalog}, base.assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}

	g := vendorFixture()
	var urls []Relation
	for i := 0; i < 50; i++ {
		u := fmt.Sprintf("https://colgate.edu/page%d", i)
		g.assets[u] = Asset{ID: u, Type: "URL", Key: u, Content: map[string]any{"url": u}}
		urls = append(urls, Relation{ID: "domain-" + u, FromID: u, ToID: "colgate.edu", Label: "domain",
			Type: "SimpleRelation"})
	}
	// Stored first, so a walk in stored order would admit the URLs first.
	g.links = append(urls, g.links...)

	r, err := searchThirdPartiesWithin(context.Background(), g, vendorCatalog{testOAMCatalog},
		g.assets["colgate.edu"], LensLimits{MaxAssets: want.Footprint + 5})
	if err != nil {
		t.Fatal(err)
	}
	if r.Footprint != want.Footprint+5 || r.FootprintTypes["URL"] != 5 || r.Reason != "controlled asset limit" {
		t.Errorf("footprint %d with %d URLs (%q), want %d with 5", r.Footprint, r.FootprintTypes["URL"], r.Reason,
			want.Footprint+5)
	}
	for name, kind := range vendorNames(&want) {
		if vendorNames(&r)[name] != kind {
			t.Errorf("vendor %s (%s) lost to URLs: %v", name, kind, vendorNames(&r))
		}
	}
}

// A registration contact with no organization is the subject's own when its
// email is in one of the subject's domains, and is named by its email
// domain otherwise, never by its RDAP URL.
func TestThirdPartyLensNamesContactsByEmail(t *testing.T) {
	g := vendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	add("https://rdap.arin.net/registry/entity/RG3622-ARIN", "ContactRecord", nil)
	add("email-own", "Identifier", map[string]any{"id": "netops@colgate.edu", "id_type": "email"})
	add("https://rdap.arin.net/registry/entity/NOC1-ARIN", "ContactRecord", nil)
	add("email-out", "Identifier", map[string]any{"id": "noc@acmehosting.com", "id_type": "email"})
	add("https://rdap.arin.net/registry/entity/NONE-ARIN", "ContactRecord", nil)
	link("ipnet-own", "technical_contact", "https://rdap.arin.net/registry/entity/RG3622-ARIN")
	link("https://rdap.arin.net/registry/entity/RG3622-ARIN", "id", "email-own")
	link("dr", "technical_contact", "https://rdap.arin.net/registry/entity/NOC1-ARIN")
	link("https://rdap.arin.net/registry/entity/NOC1-ARIN", "id", "email-out")
	link("dr", "technical_contact", "https://rdap.arin.net/registry/entity/NONE-ARIN")

	r, err := searchThirdParties(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}

	got := vendorNames(&r)
	if _, ok := got["https://rdap.arin.net/registry/entity/RG3622-ARIN"]; ok {
		t.Errorf("the subject's own contact is a vendor: %v", got)
	}
	if got["acmehosting.com"] == "" {
		t.Errorf("outside contact not named by its email domain: %v", got)
	}
	// A contact with nothing to name it by names no party: its record's key
	// is an RDAP URL, not a vendor.
	if _, ok := got["https://rdap.arin.net/registry/entity/NONE-ARIN"]; ok {
		t.Errorf("contact without an email named by its record: %v", got)
	}
}

// A redacted WHOIS contact with no organization or email does not name a
// party by its record's key; the domain it is the contact for does.
func TestThirdPartyLensSkipsAnonymousContacts(t *testing.T) {
	g := vendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}

	add("edge.cdn.example", "FQDN", map[string]any{"name": "edge.cdn.example"})
	add("cdn.example", "FQDN", map[string]any{"name": "cdn.example"})
	add("dr-cdn", "DomainRecord", map[string]any{"domain": "cdn.example"})
	key := "whois.cdn.example, cdn.example, Admin Contact Info"
	add(key, "ContactRecord", map[string]any{"discovered_at": key})
	link("portal.colgate.edu", "dns_record", "edge.cdn.example", "BasicDNSRelation")
	link("cdn.example", "node", "edge.cdn.example", "SimpleRelation")
	link("cdn.example", "registration", "dr-cdn", "SimpleRelation")
	link("dr-cdn", "admin_contact", key, "SimpleRelation")

	r, err := searchThirdParties(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}

	got := vendorNames(&r)
	if _, ok := got[key]; ok {
		t.Errorf("an anonymous contact's record key named a vendor: %v", got)
	}
	if got["cdn.example"] == "" {
		t.Errorf("the provider's domain does not name it: %v", got)
	}
}

// descentCounter counts the paged reads of one asset's outgoing node edges.
type descentCounter struct {
	pagedVendorGraph
	id    string
	reads *int
}

func (g descentCounter) EdgesPage(ctx context.Context, id, dir, label string, since time.Time, cursor string,
	limit int) ([]Relation, string, error) {
	if id == g.id && dir == "out" && label == "node" {
		*g.reads++
	}
	return g.pagedVendorGraph.EdgesPage(ctx, id, dir, label, since, cursor, limit)
}

// A provider's domain with more names than one read (amazonaws.com) is
// reached only to find who controls the name the subject uses: its
// descendants are never paged, and the report is not partial for them.
func TestThirdPartyLensDoesNotDescendOutsideTheFootprint(t *testing.T) {
	defer func(n int) { lensMaxPerLabel = n }(lensMaxPerLabel)
	lensMaxPerLabel = 550

	g := vendorFixture()
	add := func(name string) {
		g.assets[name] = Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
	}
	add("pphosted.com")
	links := []Relation{{ID: "node-mx1", FromID: "pphosted.com", ToID: "mx1.pphosted.com", Label: "node",
		Type: "SimpleRelation"}}
	for i := 0; i < MaxEdgeRead+100; i++ {
		name := fmt.Sprintf("mx%d.customer%d.pphosted.com", i, i)
		add(name)
		links = append(links, Relation{ID: "node-" + name, FromID: "pphosted.com", ToID: name, Label: "node",
			Type: "SimpleRelation"})
	}
	g.links = append(links, g.links...)

	reads := 0
	pg := descentCounter{pagedVendorGraph: pagedVendorGraph{vendorGraph: g, pages: new(int)}, id: "pphosted.com",
		reads: &reads}
	r, err := searchThirdParties(context.Background(), pg, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated {
		t.Errorf("partial for a provider's names: %s", r.Reason)
	}
	if reads != 0 {
		t.Errorf("paged pphosted.com's descendants %d time(s)", reads)
	}
	if _, ok := vendorNames(&r)["pphosted.com"]; !ok {
		t.Errorf("mail provider missing: %v", vendorNames(&r))
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
	org := func(id, name string) Asset {
		return Asset{ID: id, Type: "Organization", Content: map[string]any{"name": name}}
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
	org := func(id, name string) Asset {
		return Asset{ID: id, Type: "Organization", Content: map[string]any{"name": name}}
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
	main := Asset{ID: "o1", Type: "Organization", Content: map[string]any{"name": "northrop grumman corp."}}
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
