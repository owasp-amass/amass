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

func relatedDomainsGraph() graphtest.FakeGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	org := func(id, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Organization", Key: name + ":1",
			Content: map[string]any{"name": name}}
	}
	contact := func(id string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "ContactRecord", Key: id, Content: map[string]any{}}
	}
	domainRec := func(id, domain string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "DomainRecord", Key: domain, Content: map[string]any{"domain": domain}}
	}
	fqdn := func(id, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
	}
	cert := func(id string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "TLSCertificate", Key: id, Content: map[string]any{}}
	}
	link := func(from, to, label string) {
		g.Links = append(g.Links, graph.Relation{ID: label + from + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	// A real organization. Registrant signal: two apex domains registered
	// through one contact.
	org("acme", "Acme Corporation")
	contact("cr1")
	link("cr1", "acme", "organization")
	domainRec("dr1", "acme.com")
	domainRec("dr2", "acme.net")
	link("dr1", "cr1", "registrant_contact")
	link("dr2", "cr1", "registrant_contact")

	// Certificate signal: a cert whose subject contact names the org, covering
	// acme.com (also found via registrant) and a new apex acme.io.
	cert("cert1")
	link("cert1", "cr1", "subject_contact")
	fqdn("fq_www_acme_com", "www.acme.com")
	fqdn("fq_acme_io", "acme.io")
	link("cert1", "fq_www_acme_com", "common_name")
	link("cert1", "fq_acme_io", "san_dns_name")

	// Name-server signal: acme.com's own name server also serves acme-labs.org,
	// a domain not otherwise tied to the org.
	fqdn("ns_acme", "ns1.acme-dns.com")
	link("dr1", "ns_acme", "name_server")
	domainRec("dr4", "acme-labs.org")
	link("dr4", "ns_acme", "name_server")

	// Official-website signal: the org publishes acme.org as its website
	// (Organization --website--> URL --domain--> FQDN).
	g.Assets["url_acme_org"] = graph.Asset{ID: "url_acme_org", Type: "URL", Key: "https://acme.org",
		Content: map[string]any{"url": "https://acme.org"}}
	link("acme", "url_acme_org", "website")
	fqdn("fq_acme_org", "acme.org")
	link("url_acme_org", "fq_acme_org", "domain")

	// A privacy-proxy "organization" shared by an unrelated domain: never
	// correlated on.
	org("proxy", "Domains By Proxy, LLC")
	contact("cr2")
	link("cr2", "proxy", "organization")
	domainRec("dr3", "stranger.com")
	link("dr3", "cr2", "registrant_contact")

	// DNS-record signals: acme.net's apex FQDN (registration --> dr2) shares its
	// resolved mail exchanger with acme-mail.org and its DNS name server with
	// acme-dns.net, neither otherwise tied to the org. An NS record and an MX
	// record are the same shape in OAM, found by the one shared-DNS-host pivot.
	dnsLink := func(from, to string, rrType int) {
		g.Links = append(g.Links, graph.Relation{ID: "dnsrec" + from + to, FromID: from, ToID: to,
			Label: "dns_record", Type: "BasicDNSRelation",
			Content: map[string]any{"header": map[string]any{"rr_type": rrType}}})
	}
	fqdn("fq_acme_net", "acme.net")
	link("fq_acme_net", "dr2", "registration")
	fqdn("mx_host", "mail.acme-mx.example")
	dnsLink("fq_acme_net", "mx_host", rrTypeMX)
	fqdn("fq_acme_mail", "acme-mail.org")
	dnsLink("fq_acme_mail", "mx_host", rrTypeMX)
	fqdn("dns_ns_host", "dns1.acme-ns.example")
	dnsLink("fq_acme_net", "dns_ns_host", RRTypeNS)
	fqdn("fq_acme_dns", "acme-dns.net")
	dnsLink("fq_acme_dns", "dns_ns_host", RRTypeNS)

	// Provider guard: acme.net also points its mail at a known mail provider
	// (Google Workspace, an alt*.aspmx host) and its DNS at a known managed-DNS
	// provider (Cloudflare). An unrelated domain sharing those provider hosts
	// must never be surfaced, even though few of each provider's tenants are in
	// this graph, so the apex-count cap alone would not catch them.
	fqdn("prov_mx", "alt1.aspmx.l.google.com")
	dnsLink("fq_acme_net", "prov_mx", rrTypeMX)
	fqdn("fq_stranger_mail", "stranger-mail.com")
	dnsLink("fq_stranger_mail", "prov_mx", rrTypeMX)
	fqdn("prov_ns", "quip.ns.cloudflare.com")
	dnsLink("fq_acme_net", "prov_ns", RRTypeNS)
	fqdn("fq_stranger_dns", "stranger-dns.com")
	dnsLink("fq_stranger_dns", "prov_ns", RRTypeNS)

	return g
}

func TestFindRelatedDomainsSignals(t *testing.T) {
	g := relatedDomainsGraph()

	r, err := FindRelatedDomains(context.Background(), g, "acme")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]HorizontalDomain{}
	for _, d := range r.Domains {
		got[d.Domain] = d
	}
	for _, want := range []string{"acme.com", "acme.net", "acme.io", "acme-labs.org", "acme.org",
		"acme-mail.org", "acme-dns.net"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing related domain %q; got %+v", want, r.Domains)
		}
	}
	// acme.org comes only from the official-website signal.
	if d := got["acme.org"]; d.Confidence != relatedWebsiteConfidence || len(d.Signals) != 1 {
		t.Errorf("acme.org should come from the official-website signal: %+v", d)
	}
	// acme.io comes only from the certificate signal.
	if d := got["acme.io"]; len(d.Witness) == 0 || d.Confidence != relatedCertConfidence {
		t.Errorf("acme.io should carry the cert signal: %+v", d)
	}
	// acme-labs.org comes only from the shared-name-server signal.
	if d := got["acme-labs.org"]; d.Confidence != relatedNSConfidence || len(d.Signals) != 1 {
		t.Errorf("acme-labs.org should come from the name-server signal: %+v", d)
	}
	// acme-mail.org comes only from the shared mail-exchanger (MX) signal.
	if d := got["acme-mail.org"]; d.Confidence != relatedMXConfidence || len(d.Signals) != 1 {
		t.Errorf("acme-mail.org should come from the shared-MX signal: %+v", d)
	}
	// acme-dns.net comes only from the shared-name-server signal, via its DNS record.
	if d := got["acme-dns.net"]; d.Confidence != relatedNSConfidence || len(d.Signals) != 1 {
		t.Errorf("acme-dns.net should come from the DNS name-server signal: %+v", d)
	}
	// A domain sharing only a known provider's mail exchanger or name server is
	// never surfaced: the provider guard skips the host whatever the coverage.
	if _, ok := got["stranger-mail.com"]; ok {
		t.Error("a domain sharing a known mail provider (Google Workspace) must not be correlated on")
	}
	if _, ok := got["stranger-dns.com"]; ok {
		t.Error("a domain sharing a known managed-DNS provider (Cloudflare) must not be correlated on")
	}
	// acme.com is found by all three signals, and corroboration ranks it above
	// any single signal (noisy-OR of the catalog weights).
	if d := got["acme.com"]; len(d.Signals) != 3 || len(d.SignalIDs) != 3 {
		t.Errorf("acme.com should have registrant, cert and name-server signals: %+v", d)
	}
	if d := got["acme.com"]; d.Confidence <= relatedCertConfidence {
		t.Errorf("acme.com confidence %d should exceed any single signal", d.Confidence)
	}
}

func TestHorizontalExpansionPartition(t *testing.T) {
	g := relatedDomainsGraph()

	r, err := FindRelatedDomains(context.Background(), g, "acme")
	if err != nil {
		t.Fatal(err)
	}

	expand, review := HorizontalExpansion(r)
	in := func(ds []HorizontalDomain, name string) bool {
		for _, d := range ds {
			if d.Domain == name {
				return true
			}
		}
		return false
	}

	// Every domain with a strong signal (registrant, cert or official website)
	// is in the expand set.
	for _, name := range []string{"acme.com", "acme.net", "acme.io", "acme.org"} {
		if !in(expand, name) {
			t.Errorf("%s has a strong signal and should be in the expand set", name)
		}
	}
	// acme-labs.org is tied only by a shared name server (supporting), so it
	// needs review rather than auto-expanding.
	if !in(review, "acme-labs.org") {
		t.Errorf("acme-labs.org (name server only) should need review, got expand=%v review=%v", expand, review)
	}
	if in(expand, "acme-labs.org") {
		t.Error("a lone shared-name-server match must not auto-expand scope")
	}
}

func TestFindRelatedDomainsSkipsPrivacyProxy(t *testing.T) {
	g := relatedDomainsGraph()

	r, err := FindRelatedDomains(context.Background(), g, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Domains) != 0 {
		t.Errorf("a privacy-proxy organization must not be correlated on, got %+v", r.Domains)
	}
}
