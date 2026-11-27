// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamcontact "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// tieGraph is a small stored graph for the walk from a lead to the targets.
type tieGraph struct {
	*leadStore
	assets map[string]oam.Asset
	links  [][2]string
}

func newTieGraph() *tieGraph {
	return &tieGraph{leadStore: newLeadStore(), assets: map[string]oam.Asset{}}
}

func (g *tieGraph) add(id string, a oam.Asset) {
	g.assets[id] = a
	g.entities[id] = &dbt.Entity{ID: id, Asset: a}
}

func (g *tieGraph) link(from, to string) { g.links = append(g.links, [2]string{from, to}) }

func (g *tieGraph) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	if e, ok := g.entities[id]; ok {
		return e, nil
	}
	return nil, errors.New("entity not found")
}

func (g *tieGraph) linkEdges(id string, out bool) ([]*dbt.Edge, error) {
	var edges []*dbt.Edge
	for i, l := range g.links {
		if (out && l[0] == id) || (!out && l[1] == id) {
			// the ends carry only IDs, as the repository's edges do
			edges = append(edges, &dbt.Edge{ID: fmt.Sprintf("e%d", i), FromEntity: &dbt.Entity{ID: l[0]},
				ToEntity: &dbt.Entity{ID: l[1]}})
		}
	}
	if len(edges) == 0 {
		return nil, fmt.Errorf("zero edges found for entity %s", id)
	}
	return edges, nil
}

func (g *tieGraph) IncomingEdges(_ context.Context, e *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.Edge, error) {
	return g.linkEdges(e.ID, false)
}

func (g *tieGraph) OutgoingEdges(_ context.Context, e *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.Edge, error) {
	return g.linkEdges(e.ID, true)
}

func uticaTargets() LeadTargets {
	return LeadTargets{Domains: []string{"utica.edu"}, Prefixes: []netip.Prefix{netip.MustParsePrefix("72.237.4.0/24")},
		ASNs: []int{26808}}
}

func TestLeadTargetsMatch(t *testing.T) {
	tg := uticaTargets()
	for _, tc := range []struct {
		a    oam.Asset
		want bool
	}{
		{&oamdns.FQDN{Name: "utica.edu"}, true},
		{&oamdns.FQDN{Name: "VPN.Utica.edu."}, true},
		{oamdns.FQDN{Name: "sslvpn.utica.edu"}, true},
		{&oamdns.FQDN{Name: "notutica.edu"}, false},
		{&oamnet.IPAddress{Address: netip.MustParseAddr("72.237.4.91")}, true},
		{&oamnet.IPAddress{Address: netip.MustParseAddr("72.237.5.1")}, false},
		{&oamnet.Netblock{CIDR: netip.MustParsePrefix("72.237.4.128/25")}, true},
		{&oamnet.Netblock{CIDR: netip.MustParsePrefix("72.237.0.0/16")}, false},
		{&oamnet.AutonomousSystem{Number: 26808}, true},
		{&oamorg.Organization{Name: "Utica University"}, false},
	} {
		if got := tg.matches(tc.a); got != tc.want {
			t.Errorf("matches(%v) = %v, want %v", tc.a, got, tc.want)
		}
	}
}

// A lead counts as confirmed only when stored relations tie it to the run's
// targets; an organization that collected only records of its own does not.
func TestLeadConfirmedNeedsATie(t *testing.T) {
	ctx := context.Background()
	g := newTieGraph()
	g.add("utica.edu", &oamdns.FQDN{Name: "utica.edu"})
	g.add("www", &oamurl.URL{Raw: "https://www.utica.edu/"})
	g.add("college", &oamorg.Organization{Name: "Utica University"})
	g.add("cr", &oamcontact.ContactRecord{DiscoveredAt: "https://rdap.example/utica"})
	g.link("college", "www")
	g.link("www", "utica.edu")
	g.link("cr", "college")

	// a phone on the college's contact record: phone, record, college, URL, domain
	g.add("phone", &oamcontact.Phone{Raw: "+16074314000"})
	g.link("cr", "phone")

	// an organization named in passing that collected only its own funding:
	// its awards share a payer with the college's, which is not a tie
	g.add("tiaa", &oamorg.Organization{Name: "Teachers Insurance and Annuity Association of America"})
	g.add("tiaa-acct", &oamacct.Account{ID: "tiaa"})
	g.add("award", &oamfin.FundsTransfer{ID: "award-1"})
	g.add("agency-acct", &oamacct.Account{ID: "agency"})
	g.add("college-acct", &oamacct.Account{ID: "college"})
	g.add("college-award", &oamfin.FundsTransfer{ID: "award-2"})
	g.link("tiaa", "tiaa-acct")
	g.link("award", "tiaa-acct")
	g.link("award", "agency-acct")
	g.link("college-award", "agency-acct")
	g.link("college-award", "college-acct")
	g.link("college", "college-acct")

	// a host under the target domain the engine resolved, and one it did not
	g.add("vpn", &oamdns.FQDN{Name: "vpn.utica.edu"})
	g.add("ip", &oamnet.IPAddress{Address: netip.MustParseAddr("72.237.4.91")})
	g.link("vpn", "ip")
	g.add("lonely", &oamdns.FQDN{Name: "lonely.utica.edu"})

	tg := uticaTargets()
	for id, want := range map[string]bool{"phone": true, "college": true, "tiaa": false, "vpn": true, "lonely": false} {
		if got := LeadConfirmed(ctx, g, id, tg); got != want {
			t.Errorf("LeadConfirmed(%s) = %v, want %v", id, got, want)
		}
	}
	// without targets, any relation confirms a lead, as before
	if !LeadConfirmed(ctx, g, "tiaa", LeadTargets{}) {
		t.Error("without targets, a linked lead was not confirmed")
	}
}

// A hub is checked but not walked through, so a shared provider does not tie
// its other customers to the target.
func TestLeadTieSkipsHubs(t *testing.T) {
	ctx := context.Background()
	g := newTieGraph()
	g.add("utica.edu", &oamdns.FQDN{Name: "utica.edu"})
	g.add("provider", &oamorg.Organization{Name: "Big Provider"})
	g.add("lead", &oamorg.Organization{Name: "Some Customer Inc."})
	g.link("lead", "provider")
	g.link("utica.edu", "provider")
	for i := range tieMaxEdges {
		id := fmt.Sprintf("customer-%d", i)
		g.add(id, &oamdns.FQDN{Name: id + ".example"})
		g.link(id, "provider")
	}

	if LeadConfirmed(ctx, g, "lead", uticaTargets()) {
		t.Error("a lead was tied to the target through a hub")
	}
}

func TestNewLeadTargets(t *testing.T) {
	got := NewLeadTargets([]oam.Asset{
		oamdns.FQDN{Name: "Utica.EDU."},
		oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.10")},
		oamnet.Netblock{CIDR: netip.MustParsePrefix("72.237.4.7/24")},
		oamnet.AutonomousSystem{Number: 26808},
		oamcontact.Phone{E164: "+16074314000"},
	})
	if len(got.Domains) != 1 || got.Domains[0] != "utica.edu" ||
		len(got.Prefixes) != 2 || got.Prefixes[0] != netip.MustParsePrefix("192.0.2.10/32") ||
		got.Prefixes[1] != netip.MustParsePrefix("72.237.4.0/24") || len(got.ASNs) != 1 || got.ASNs[0] != 26808 {
		t.Fatalf("NewLeadTargets = %+v", got)
	}
	if !(LeadTargets{}).Empty() || got.Empty() {
		t.Error("Empty is wrong")
	}
}
