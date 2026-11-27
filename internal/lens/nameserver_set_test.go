// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// emptyValueGraph answers value searches with nothing, so the value signals
// (the name server set among them) run over the stored relationships.
type emptyValueGraph struct{ graphtest.VendorGraph }

func (emptyValueGraph) FindByTagValue(context.Context, string, string, string, bool, int) ([]graph.Asset, bool, error) {
	return nil, false, nil
}

func (emptyValueGraph) FindByAttribute(context.Context, string, string, string, bool, int) ([]graph.Asset, bool, error) {
	return nil, false, nil
}

// A name server set belongs to one provider only when every server does.
func TestNameServerSetProvider(t *testing.T) {
	for _, tc := range []struct {
		hosts      []string
		provider   string
		assignment string
	}{
		{[]string{"ns-12.awsdns-01.com", "ns-1500.awsdns-58.org", "ns-700.awsdns-23.net", "ns-1999.awsdns-12.co.uk"},
			"Amazon Route 53", AssignmentUniqueSet},
		{[]string{"ada.ns.cloudflare.com.", "bob.ns.cloudflare.com"}, "Cloudflare", AssignmentAccount},
		{[]string{"ns-cloud-a1.googledomains.com", "ns-cloud-a2.googledomains.com"}, "Google Cloud DNS", AssignmentShared},
		{[]string{"ada.ns.cloudflare.com", "ns-12.awsdns-01.com"}, "", ""},
		{[]string{"ns1.example.edu", "ns2.example.edu"}, "", ""},
	} {
		p, ok := nameServerSetProvider(tc.hosts)
		if p.Provider != tc.provider || p.Assignment != tc.assignment || ok != (tc.provider != "") {
			t.Errorf("nameServerSetProvider(%v) = %q %q %v, want %q %q", tc.hosts, p.Provider, p.Assignment, ok,
				tc.provider, tc.assignment)
		}
	}
}

// The registration sharing owasp.org's name server set is a candidate: on
// the strong delegation-set signal when the set is a full Route 53 set, on
// the supporting signal for a Cloudflare pair, and not at all for servers a
// provider's whole customer base shares.
func TestNameServerSetSignals(t *testing.T) {
	for _, tc := range []struct {
		servers []string
		want    string
	}{
		{[]string{"ns-12.awsdns-01.com", "ns-1500.awsdns-58.org", "ns-700.awsdns-23.net", "ns-1999.awsdns-12.co.uk"},
			"dns-provider-delegation-set"},
		{[]string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}, "shared-nameserver-set"},
		{[]string{"ns-cloud-a1.googledomains.com", "ns-cloud-a2.googledomains.com"}, ""},
	} {
		g := emptyValueGraph{graphtest.VendorFixture()}
		var links []graph.Relation
		for _, l := range g.Links {
			if !(l.FromID == "dr" && l.Label == "name_server") {
				links = append(links, l)
			}
		}
		g.Links = links
		g.Assets["dr-sib"] = graph.Asset{ID: "dr-sib", Type: "DomainRecord", Key: "owasp-sibling.org",
			Content: map[string]any{"domain": "owasp-sibling.org"}}
		for _, ns := range tc.servers {
			id := "ns-" + ns
			g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: ns, Content: map[string]any{"name": ns}}
			for _, dr := range []string{"dr", "dr-sib"} {
				g.Links = append(g.Links, graph.Relation{ID: dr + "-ns-" + ns, FromID: dr, ToID: id,
					Label: "name_server", Type: "SimpleRelation"})
			}
		}

		r, err := SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
			g.Assets["owasp"])
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		for _, c := range r.Candidates {
			if c.AssetID != "dr-sib" {
				continue
			}
			for _, s := range c.Signals {
				if s.Signal == "dns-provider-delegation-set" || s.Signal == "shared-nameserver-set" {
					got = s.Signal
				}
			}
		}
		if got != tc.want {
			t.Errorf("servers %v: signal %q, want %q (candidates %+v)", tc.servers, got, tc.want, r.Candidates)
		}
	}
}
