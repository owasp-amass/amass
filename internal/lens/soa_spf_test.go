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

// soaGraph gives acme.net (an apex of the organization) an SOA mailbox and
// primary name server, and acme-ops.org the same mailbox.
func soaGraph(mailbox, mname string) graphtest.FakeGraph {
	g := relatedDomainsGraph()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, to, label string, content map[string]any) {
		g.Links = append(g.Links, graph.Relation{ID: label + from + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation", Content: content})
	}
	add("mb", "Identifier", "email:"+mailbox, map[string]any{"unique_id": "email:" + mailbox, "id": mailbox,
		"id_type": "email"})
	add("fq_acme_ops", "FQDN", "acme-ops.org", map[string]any{"name": "acme-ops.org"})
	link("fq_acme_net", "mb", "soa_rname", nil)
	link("fq_acme_ops", "mb", "soa_rname", nil)
	add("mname", "FQDN", mname, map[string]any{"name": mname})
	soa := map[string]any{"header": map[string]any{"rr_type": rrTypeSOA}}
	link("fq_acme_net", "mname", "dns_record", soa)
	link("fq_acme_ops", "mname", "dns_record", soa)
	return g
}

func soaSignal(t *testing.T, g graphtest.FakeGraph) []string {
	t.Helper()
	r, err := FindRelatedDomains(context.Background(), g, nil, "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Domains {
		if d.Domain == "acme-ops.org" {
			return d.SignalIDs
		}
	}
	return nil
}

func TestSOAMailboxPivot(t *testing.T) {
	// a mailbox at the organization's own domain is the strong signal
	if got := soaSignal(t, soaGraph("hostmaster@acme.net", "ns1.acme.net")); len(got) != 1 ||
		got[0] != SigSOAMailboxOwn {
		t.Errorf("own mailbox: %v", got)
	}
	// an outside mailbox is the supporting one
	if got := soaSignal(t, soaGraph("dns@agency.example", "ns1.acme.net")); len(got) != 1 ||
		got[0] != SigSharedSOAMailbox {
		t.Errorf("outside mailbox: %v", got)
	}
	// a DNS host's default mailbox gives nothing: at its primary's domain, or
	// with a managed-DNS provider's primary
	if got := soaSignal(t, soaGraph("hostmaster@registrar-servers.example", "dns1.registrar-servers.example")); got != nil {
		t.Errorf("host default mailbox: %v", got)
	}
	if got := soaSignal(t, soaGraph("dns@agency.example", "quip.ns.cloudflare.com")); got != nil {
		t.Errorf("managed-DNS provider zone: %v", got)
	}
}

func TestSPFDeclaredRanges(t *testing.T) {
	g := relatedInfraGraph()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, to, label string) {
		g.Links = append(g.Links, graph.Relation{ID: label + from + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}
	add("dr", "DomainRecord", "acme.example", map[string]any{"domain": "acme.example"})
	add("apex", "FQDN", "acme.example", map[string]any{"name": "acme.example"})
	link("dr", "cr1", "registrant")
	link("apex", "dr", "registration")
	add("nb-spf", "Netblock", "198.18.32.0/24", map[string]any{"cidr": "198.18.32.0/24"})
	link("apex", "nb-spf", "spf_authorizes")
	add("ip-spf", "IPAddress", "198.18.40.9", map[string]any{"address": "198.18.40.9"})
	add("nb-ip", "Netblock", "198.18.40.0/24", map[string]any{"cidr": "198.18.40.0/24"})
	link("nb-ip", "ip-spf", "contains")
	link("apex", "ip-spf", "spf_authorizes")
	add("nb-cloud", "Netblock", "198.18.48.0/24", map[string]any{"cidr": "198.18.48.0/24"})
	add("cloud", "Organization", "Cloud", map[string]any{"name": "Example Cloud"})
	link("nb-cloud", "cloud", "provider")
	link("apex", "nb-cloud", "spf_authorizes")

	r, err := FindRelatedInfrastructure(context.Background(), g, "acme")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]InfrastructureAsset{}
	for _, a := range r.Assets {
		got[a.Asset] = a
	}
	for _, cidr := range []string{"198.18.32.0/24", "198.18.40.0/24"} {
		if a, ok := got[cidr]; !ok || len(a.SignalIDs) != 1 || a.SignalIDs[0] != SigSPFDeclaredRange {
			t.Errorf("%s: %+v", cidr, a)
		}
	}
	if _, ok := got["198.18.48.0/24"]; ok {
		t.Error("a cloud provider's netblock was related")
	}
	expand, _ := InfrastructureExpansion(r)
	for _, a := range expand {
		if a.Asset == "198.18.32.0/24" {
			t.Error("an SPF range alone expanded scope")
		}
	}
}
