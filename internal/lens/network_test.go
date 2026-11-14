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

// networkFixture adds to the vendor fixture a name resolving to an address
// of the university's space that no netblock is stored for, and a second
// registered netblock none of its names use.
func networkFixture() graphtest.VendorGraph {
	g := graphtest.VendorFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	add("mail.colgate.edu", "FQDN", "mail.colgate.edu", map[string]any{"name": "mail.colgate.edu"})
	add("ip-loose", "IPAddress", "149.43.9.9", map[string]any{"address": "149.43.9.9"})
	link("colgate.edu", "node", "mail.colgate.edu")
	g.Links = append(g.Links, graph.Relation{ID: "mail-a", FromID: "mail.colgate.edu", ToID: "ip-loose",
		Label: "dns_record", Type: "BasicDNSRelation"})

	// Names hosted through aliases: one to a provider name with a stored
	// address, one to a provider name with none.
	cname := func(from, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-cname", FromID: from, ToID: to, Label: "dns_record",
			Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": 5}}})
	}
	for _, n := range []string{"cdn.colgate.edu", "d1.cloudfront.net", "shop.colgate.edu", "colgate.myshopify.com"} {
		add(n, "FQDN", n, map[string]any{"name": n})
	}
	link("colgate.edu", "node", "cdn.colgate.edu")
	link("colgate.edu", "node", "shop.colgate.edu")
	cname("cdn.colgate.edu", "d1.cloudfront.net")
	cname("shop.colgate.edu", "colgate.myshopify.com")
	add("ip-aws", "IPAddress", "13.32.1.1", map[string]any{"address": "13.32.1.1"})
	add("ip-aws2", "IPAddress", "13.32.1.2", map[string]any{"address": "13.32.1.2"})
	add("nb-aws", "Netblock", "13.32.0.0/15", map[string]any{"cidr": "13.32.0.0/15"})
	add("as-aws", "AutonomousSystem", "16509", map[string]any{"number": 16509})
	add("autnum-aws", "AutnumRecord", "AS16509", map[string]any{"handle": "AS16509", "name": "AMAZON-02"})
	for _, ip := range []string{"ip-aws", "ip-aws2"} {
		g.Links = append(g.Links, graph.Relation{ID: "cf-" + ip, FromID: "d1.cloudfront.net", ToID: ip,
			Label: "dns_record", Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": 1}}})
		link("nb-aws", "contains", ip)
	}
	link("as-aws", "announces", "nb-aws")
	link("as-aws", "registration", "autnum-aws")

	// A partner's name on an address in the university's space, by an
	// address record and by a pointer record.
	add("ip-tenant", "IPAddress", "149.43.5.5", map[string]any{"address": "149.43.5.5"})
	link("nb-own", "contains", "ip-tenant")
	for _, n := range []string{"portal.partner-co.com", "mail.partner-co.com"} {
		add(n, "FQDN", n, map[string]any{"name": n})
	}
	g.Links = append(g.Links, graph.Relation{ID: "tenant-a", FromID: "portal.partner-co.com", ToID: "ip-tenant",
		Label: "dns_record", Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": 1}}})
	link("ip-tenant", "ptr_record", "mail.partner-co.com")

	add("nb-spare", "Netblock", "2620:0:2810::/48", map[string]any{"cidr": "2620:0:2810::/48"})
	add("ipnet-spare", "IPNetRecord", "2620:0:2810::/48", map[string]any{"name": "COLGATE-V6"})
	link("nb-spare", "registration", "ipnet-spare")
	link("ipnet-spare", "registrant", "cr-colgate")
	return g
}

func TestFindNetworkInfrastructure(t *testing.T) {
	g := networkFixture()
	r, err := FindNetworkInfrastructure(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Networks) != 2 || r.Networks[0].CIDR != "149.43.0.0/16" || r.Networks[0].Names != 2 ||
		r.Networks[0].Addresses != 2 || strings.Join(r.Networks[0].Announced, ",") != "AS1289" {
		t.Fatalf("networks = %+v", r.Networks)
	}
	if len(r.Foreign) != 1 || r.Foreign[0].Domain != "partner-co.com" || r.Foreign[0].Names != 2 ||
		strings.Join(r.Foreign[0].Addresses, ",") != "149.43.5.5" {
		t.Errorf("foreign names = %+v", r.Foreign)
	}
	if strings.Join(r.Unused, ",") != "2620:0:2810::/48" || r.Networks[1].Version != 6 {
		t.Errorf("unused = %v, networks = %+v", r.Unused, r.Networks)
	}
	if len(r.ASNs) != 1 || r.ASNs[0].Number != "AS1289" || r.ASNs[0].Name != "COLGATE-UNIVERSITY" ||
		len(r.ASNs[0].Foreign) != 0 {
		t.Errorf("autonomous systems = %+v", r.ASNs)
	}
	if r.Resolved != 5 || r.Aliased != 2 || r.Unresolved != 1 || len(r.Hosting) != 4 {
		t.Fatalf("resolved %d, unresolved %d, hosting %+v", r.Resolved, r.Unresolved, r.Hosting)
	}
	// mail.colgate.edu resolves to an address with no stored netblock; its
	// range puts it in the university's own space.
	byParty := map[string]HostingShare{}
	for _, h := range r.Hosting {
		byParty[h.Party] = h
	}
	own, cdn := byParty["own"], byParty["FASTLY"]
	if !own.Own || own.Names != 2 || !strings.Contains(strings.Join(own.Examples, ","), "mail.colgate.edu") {
		t.Errorf("own hosting = %+v", own)
	}
	if cdn.Own || cdn.Party != "FASTLY" || cdn.Names != 1 || strings.Join(cdn.Networks, ",") != "151.101.0.0/16" {
		t.Errorf("provider hosting = %+v", cdn)
	}
	// An alias is hosted where its target's addresses are, counted once
	// however many addresses there are.
	if aws := byParty["AMAZON-02"]; aws.Names != 1 || strings.Join(aws.Examples, ",") != "cdn.colgate.edu" ||
		strings.Join(aws.Networks, ",") != "13.32.0.0/15" {
		t.Errorf("alias hosting = %+v", r.Hosting)
	}
	// An alias to a name with no stored address is hosted by the target's
	// domain.
	if shop := byParty["myshopify.com"]; shop.Names != 1 {
		t.Errorf("alias without an address = %+v", r.Hosting)
	}

	text := FormatNetworkReport(r)
	for _, want := range []string{"1 IPv4 and 1 IPv6 netblock(s)", "announced by AS1289",
		"its own networks: 2 (40%)", "FASTLY: 1 (20%)", "(2 through an alias)", "none of its names use (1): 2620:0:2810::/48",
		"Names with no stored address: 1", "partner-co.com: 2 name(s) on 149.43.5.5"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestFindNetworkInfrastructureLimits(t *testing.T) {
	g := networkFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
	if _, err := FindNetworkInfrastructure(context.Background(), g, nil, g.Assets["colgate.edu"],
		LensLimits{}); err == nil {
		t.Error("the lens ran without relationship semantics")
	}
	if _, err := FindNetworkInfrastructure(context.Background(), g, catalog, g.Assets["colgate.edu"],
		LensLimits{MaxReads: -1}); err == nil {
		t.Error("a negative read limit was accepted")
	}

	r, err := FindNetworkInfrastructure(context.Background(), g, catalog, g.Assets["colgate.edu"],
		LensLimits{MaxReads: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || !strings.Contains(FormatNetworkReport(r), "Results are partial") {
		t.Errorf("a five-read scan was not reported as partial: %+v", r)
	}
}
