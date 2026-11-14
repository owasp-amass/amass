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
		r.Networks[0].Addresses != 1 || strings.Join(r.Networks[0].Announced, ",") != "AS1289" {
		t.Fatalf("networks = %+v", r.Networks)
	}
	if strings.Join(r.Unused, ",") != "2620:0:2810::/48" || r.Networks[1].Version != 6 {
		t.Errorf("unused = %v, networks = %+v", r.Unused, r.Networks)
	}
	if len(r.ASNs) != 1 || r.ASNs[0].Number != "AS1289" || r.ASNs[0].Name != "COLGATE-UNIVERSITY" ||
		len(r.ASNs[0].Foreign) != 0 {
		t.Errorf("autonomous systems = %+v", r.ASNs)
	}
	if r.Resolved != 3 || r.Unresolved != 1 || len(r.Hosting) != 2 {
		t.Fatalf("resolved %d, unresolved %d, hosting %+v", r.Resolved, r.Unresolved, r.Hosting)
	}
	// mail.colgate.edu resolves to an address with no stored netblock; its
	// range puts it in the university's own space.
	own, cdn := r.Hosting[0], r.Hosting[1]
	if !own.Own || own.Names != 2 || !strings.Contains(strings.Join(own.Examples, ","), "mail.colgate.edu") {
		t.Errorf("own hosting = %+v", own)
	}
	if cdn.Own || cdn.Party != "FASTLY" || cdn.Names != 1 || strings.Join(cdn.Networks, ",") != "151.101.0.0/16" {
		t.Errorf("provider hosting = %+v", cdn)
	}

	text := FormatNetworkReport(r)
	for _, want := range []string{"1 IPv4 and 1 IPv6 netblock(s)", "announced by AS1289",
		"its own networks: 2 (67%)", "FASTLY: 1 (33%)", "none of its names use (1): 2620:0:2810::/48",
		"Names with no stored address: 1"} {
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
