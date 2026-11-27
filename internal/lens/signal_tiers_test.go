// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// A name server or mail exchanger inside the organization's own domains, and
// a domain that sends all its mail through the organization, are the strong
// tiers of their signals: they expand scope.
func TestStrongSignalTiers(t *testing.T) {
	g := relatedDomainsGraph()
	fqdn := func(id, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
	}
	dnsLink := func(from, to string, rrType int) {
		g.Links = append(g.Links, graph.Relation{ID: "tier" + from + to, FromID: from, ToID: to,
			Label: "dns_record", Type: "BasicDNSRelation",
			Content: map[string]any{"header": map[string]any{"rr_type": rrType}}})
	}
	link := func(from, to, label string) {
		g.Links = append(g.Links, graph.Relation{ID: label + from + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	fqdn("ns_own", "ns1.acme.net")
	dnsLink("fq_acme_net", "ns_own", RRTypeNS)
	fqdn("fq_sister", "acme-sister.org")
	dnsLink("fq_sister", "ns_own", RRTypeNS)

	fqdn("mx_own", "mail.acme.net")
	dnsLink("fq_acme_net", "mx_own", rrTypeMX)
	fqdn("fq_mx2", "acme-mx2.org")
	dnsLink("fq_mx2", "mx_own", rrTypeMX)

	fqdn("fq_spf_only", "spf-only.example")
	link("fq_spf_only", "fq_acme_net", "spf_authorizes")

	r, err := FindRelatedDomains(context.Background(), g, nil, "acme")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]HorizontalDomain{}
	for _, d := range r.Domains {
		got[d.Domain] = d
	}
	for domain, sig := range map[string]string{"acme-sister.org": SigNameServerOwn, "acme-mx2.org": SigMXOwn,
		"spf-only.example": SigSPFExclusive, "acme-dns.net": SigSharedNameServer, "acme-mail.org": SigSharedMX,
		"spf-pub.example": SigSPFAuthorizes} {
		d, ok := got[domain]
		if !ok || len(d.SignalIDs) != 1 || d.SignalIDs[0] != sig {
			t.Errorf("%s: %+v, want %s alone", domain, d, sig)
		}
	}

	expand, review := HorizontalExpansion(r)
	in := func(list []HorizontalDomain, d string) bool {
		for _, x := range list {
			if x.Domain == d {
				return true
			}
		}
		return false
	}
	for _, d := range []string{"acme-sister.org", "acme-mx2.org", "spf-only.example"} {
		if !in(expand, d) {
			t.Errorf("%s should expand", d)
		}
	}
	for _, d := range []string{"acme-dns.net", "acme-mail.org", "spf-pub.example"} {
		if !in(review, d) {
			t.Errorf("%s should need review", d)
		}
	}
}
