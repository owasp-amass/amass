// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/lens"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// The network lens reads what the enumeration stores for address space:
// netblock CIDRs and their registrations, autonomous systems and the
// prefixes they announce, and the addresses names resolve to.
func TestNetworkInfrastructureOnSQLite(t *testing.T) {
	checkNetworkInfrastructure(t, openSQLite(t, "network.db"))
}

func checkNetworkInfrastructure(t *testing.T, repo repository.Repository) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	org := f.asset(&oamorg.Organization{ID: "example:1", Name: "Example University"})
	registrant := func(rec *dbt.Entity, url string) {
		cr := f.asset(&contact.ContactRecord{DiscoveredAt: url})
		f.edge(rec, cr, "registrant", "RDAP")
		f.edge(cr, org, "organization", "RDAP")
	}
	resolve := func(name *dbt.Entity, addr string) *dbt.Entity {
		ip := f.asset(&network.IPAddress{Address: netip.MustParseAddr(addr), Type: "IPv4"})
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: name, ToEntity: ip,
			Relation: &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}}); err != nil {
			t.Fatal(err)
		}
		return ip
	}
	netblock := func(cidr string) *dbt.Entity {
		return f.asset(&network.Netblock{CIDR: netip.MustParsePrefix(cidr), Type: "IPv4"})
	}
	as := func(number int, name string) (*dbt.Entity, *dbt.Entity) {
		a := f.asset(&network.AutonomousSystem{Number: number})
		rec := f.asset(&oamreg.AutnumRecord{Number: number, Handle: fmt.Sprintf("AS%d", number), Name: name})
		f.edge(a, rec, "registration", "RDAP")
		return a, rec
	}

	apex := f.asset(&oamdns.FQDN{Name: "example.edu"})
	dr := f.asset(&oamreg.DomainRecord{Domain: "example.edu", Name: "example.edu", ID: "example.edu"})
	f.edge(apex, dr, "registration", "RDAP")
	cr := f.asset(&contact.ContactRecord{DiscoveredAt: "https://rdap.example/example.edu"})
	f.edge(dr, cr, "registrant_contact", "RDAP")
	f.edge(cr, org, "organization", "RDAP")

	// The university's own space: a netblock registered to it and announced
	// by its own autonomous system.
	own := netblock("192.0.2.0/24")
	ipnet := f.asset(&oamreg.IPNetRecord{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Handle: "NET-192-0-2-0-1",
		Type: "IPv4", Name: "EXAMPLE-UNIV", StartAddress: netip.MustParseAddr("192.0.2.0"),
		EndAddress: netip.MustParseAddr("192.0.2.255")})
	f.edge(own, ipnet, "registration", "RDAP")
	registrant(ipnet, "https://rdap.example/net")
	ownAS, autnum := as(64500, "EXAMPLE-UNIV")
	registrant(autnum, "https://rdap.example/as")
	f.edge(ownAS, own, "announces", "BGP")

	www := f.asset(&oamdns.FQDN{Name: "www.example.edu"})
	f.edge(apex, www, "node", "DNS")
	f.edge(own, resolve(www, "192.0.2.10"), "contains", "DNS")

	// A name hosted by a provider in the provider's own space.
	cdnBlock := netblock("198.51.100.0/24")
	cdnAS, _ := as(64501, "EXAMPLE-CDN")
	f.edge(cdnAS, cdnBlock, "announces", "BGP")
	cdn := f.asset(&oamdns.FQDN{Name: "cdn.example.edu"})
	f.edge(apex, cdn, "node", "DNS")
	f.edge(cdnBlock, resolve(cdn, "198.51.100.7"), "contains", "DNS")

	adapter := Adapter{Repo: repo}
	root, err := adapter.GetAsset(ctx, apex.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := lens.FindNetworkInfrastructure(ctx, adapter, Catalog{}, root, lens.LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	text := lens.FormatNetworkReport(r)
	if len(r.Networks) != 1 || r.Networks[0].CIDR != "192.0.2.0/24" || r.Networks[0].Names != 1 ||
		strings.Join(r.Networks[0].Announced, ",") != "AS64500" {
		t.Errorf("networks = %+v\n%s", r.Networks, text)
	}
	if len(r.ASNs) != 1 || r.ASNs[0].Number != "AS64500" {
		t.Errorf("autonomous systems = %+v\n%s", r.ASNs, text)
	}
	hosts := map[string]int{}
	for _, h := range r.Hosting {
		hosts[h.Party] = h.Names
	}
	if r.Resolved != 2 || hosts["own"] != 1 || hosts["EXAMPLE-CDN"] != 1 {
		t.Errorf("hosting = %+v\n%s", r.Hosting, text)
	}
}
