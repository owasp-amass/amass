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

	// A privacy-proxy "organization" shared by an unrelated domain: never
	// correlated on.
	org("proxy", "Domains By Proxy, LLC")
	contact("cr2")
	link("cr2", "proxy", "organization")
	domainRec("dr3", "stranger.com")
	link("dr3", "cr2", "registrant_contact")

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
	for _, want := range []string{"acme.com", "acme.net", "acme.io"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing related domain %q; got %+v", want, r.Domains)
		}
	}
	// acme.io comes only from the certificate signal.
	if d := got["acme.io"]; len(d.Witness) == 0 || d.Confidence != relatedCertConfidence {
		t.Errorf("acme.io should carry the cert signal: %+v", d)
	}
	// acme.com is found by both registrant and certificate: two signals.
	if d := got["acme.com"]; len(d.Signals) != 2 {
		t.Errorf("acme.com should have both registrant and cert signals: %+v", d)
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
