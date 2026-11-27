// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// A domain with more subdomains than one read returns still shows the
// vendors its other relationships name, and the report names the label
// that stayed partial.
func TestThirdPartyLensReadsBusyAssetsByLabel(t *testing.T) {
	g := graphtest.VendorFixture()
	var nodes []graph.Relation
	for i := 0; i < graph.MaxEdgeRead+100; i++ {
		name := fmt.Sprintf("h%d.owasp.org", i)
		g.Assets[name] = graph.Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		nodes = append(nodes, graph.Relation{ID: "node-" + name, FromID: "owasp.org", ToID: name, Label: "node",
			Type: "SimpleRelation"})
	}
	// The fake reader returns edges in stored order, so the subdomains fill
	// the first read.
	g.Links = append(nodes, g.Links...)

	r, err := lens.SearchThirdParties(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"])
	if err != nil {
		t.Fatal(err)
	}
	if got := vendorNames(&r)["pphosted.com"]; got != "DNS: FQDNs" {
		t.Errorf("mail provider behind the busy domain missing: %v", vendorNames(&r))
	}
	if !r.Truncated || !strings.Contains(r.Reason, "out node edges on FQDN owasp.org") {
		t.Errorf("reason %q does not name the partial label", r.Reason)
	}
}

// Many URLs on a name do not crowd anything out: the whole footprint is
// read, so every vendor is still found.
func TestFootprintWithManyURLsKeepsVendors(t *testing.T) {
	base := graphtest.VendorFixture()
	want, err := lens.SearchThirdParties(context.Background(), base, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, base.Assets["owasp.org"])
	if err != nil {
		t.Fatal(err)
	}

	g := graphtest.VendorFixture()
	var urls []graph.Relation
	for i := 0; i < 50; i++ {
		u := fmt.Sprintf("https://owasp.org/page%d", i)
		g.Assets[u] = graph.Asset{ID: u, Type: "URL", Key: u, Content: map[string]any{"url": u}}
		urls = append(urls, graph.Relation{ID: "domain-" + u, FromID: u, ToID: "owasp.org", Label: "domain",
			Type: "SimpleRelation"})
	}
	g.Links = append(urls, g.Links...)

	r, err := lens.SearchThirdParties(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated || r.Footprint != want.Footprint+50 || r.FootprintTypes["URL"] < 50 {
		t.Errorf("footprint %d with %d URLs (%q), want %d with the 50 added", r.Footprint, r.FootprintTypes["URL"],
			r.Reason, want.Footprint+50)
	}
	for name, kind := range vendorNames(&want) {
		if vendorNames(&r)[name] != kind {
			t.Errorf("vendor %s (%s) lost: %v", name, kind, vendorNames(&r))
		}
	}
}

// A registration contact with no organization is the subject's own when its
// email is in one of the subject's domains, and is named by its email
// domain otherwise, never by its RDAP URL.
func TestThirdPartyLensNamesContactsByEmail(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	add("https://rdap.arin.net/registry/entity/RG3622-ARIN", "ContactRecord", nil)
	add("email-own", "Identifier", map[string]any{"id": "netops@owasp.org", "id_type": "email"})
	add("https://rdap.arin.net/registry/entity/NOC1-ARIN", "ContactRecord", nil)
	add("email-out", "Identifier", map[string]any{"id": "noc@acmehosting.com", "id_type": "email"})
	add("https://rdap.arin.net/registry/entity/NONE-ARIN", "ContactRecord", nil)
	link("ipnet-own", "technical_contact", "https://rdap.arin.net/registry/entity/RG3622-ARIN")
	link("https://rdap.arin.net/registry/entity/RG3622-ARIN", "id", "email-own")
	link("dr", "technical_contact", "https://rdap.arin.net/registry/entity/NOC1-ARIN")
	link("https://rdap.arin.net/registry/entity/NOC1-ARIN", "id", "email-out")
	link("dr", "technical_contact", "https://rdap.arin.net/registry/entity/NONE-ARIN")

	r, err := lens.SearchThirdParties(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"])
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
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}

	add("edge.cdn.example", "FQDN", map[string]any{"name": "edge.cdn.example"})
	add("cdn.example", "FQDN", map[string]any{"name": "cdn.example"})
	add("dr-cdn", "DomainRecord", map[string]any{"domain": "cdn.example"})
	key := "whois.cdn.example, cdn.example, Admin Contact Info"
	add(key, "ContactRecord", map[string]any{"discovered_at": key})
	link("portal.owasp.org", "dns_record", "edge.cdn.example", "BasicDNSRelation")
	link("cdn.example", "node", "edge.cdn.example", "SimpleRelation")
	link("cdn.example", "registration", "dr-cdn", "SimpleRelation")
	link("dr-cdn", "admin_contact", key, "SimpleRelation")

	r, err := lens.SearchThirdParties(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"])
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
	graphtest.PagedVendorGraph
	id    string
	reads *int
}

func (g descentCounter) EdgesPage(ctx context.Context, id, dir, label string, since time.Time, cursor string,
	limit int) ([]graph.Relation, string, error) {
	if id == g.id && dir == "out" && label == "node" {
		*g.reads++
	}
	return g.PagedVendorGraph.EdgesPage(ctx, id, dir, label, since, cursor, limit)
}

// A provider's domain with more names than one read (amazonaws.com) is
// reached only to find who controls the name the subject uses: its
// descendants are never paged, and the report is not partial for them.
func TestThirdPartyLensDoesNotDescendOutsideTheFootprint(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(name string) {
		g.Assets[name] = graph.Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
	}
	add("pphosted.com")
	links := []graph.Relation{{ID: "node-mx1", FromID: "pphosted.com", ToID: "mx1.pphosted.com", Label: "node",
		Type: "SimpleRelation"}}
	for i := 0; i < graph.MaxEdgeRead+100; i++ {
		name := fmt.Sprintf("mx%d.customer%d.pphosted.com", i, i)
		add(name)
		links = append(links, graph.Relation{ID: "node-" + name, FromID: "pphosted.com", ToID: name, Label: "node",
			Type: "SimpleRelation"})
	}
	g.Links = append(links, g.Links...)

	reads := 0
	pg := descentCounter{PagedVendorGraph: graphtest.PagedVendorGraph{VendorGraph: g, Pages: new(int)}, id: "pphosted.com",
		reads: &reads}
	r, err := lens.SearchThirdParties(context.Background(), pg, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"])
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
