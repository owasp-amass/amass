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
	// ContactRecord --organization--> Organization
	names := func(cr, o string) {
		g.Links = append(g.Links, graph.Relation{ID: "o" + cr + o, FromID: cr, ToID: o,
			Label: "organization", Type: "SimpleRelation"})
	}
	// DomainRecord --registrant_contact--> ContactRecord
	registered := func(dr, cr string) {
		g.Links = append(g.Links, graph.Relation{ID: "r" + dr + cr, FromID: dr, ToID: cr,
			Label: "registrant_contact", Type: "SimpleRelation"})
	}

	// A real organization with two apex domains registered through one contact.
	org("acme", "Acme Corporation")
	contact("cr1")
	names("cr1", "acme")
	domainRec("dr1", "acme.com")
	domainRec("dr2", "acme.net")
	registered("dr1", "cr1")
	registered("dr2", "cr1")

	// A privacy-proxy "organization" shared by an unrelated domain: must not be
	// correlated on.
	org("proxy", "Domains By Proxy, LLC")
	contact("cr2")
	names("cr2", "proxy")
	domainRec("dr3", "stranger.com")
	registered("dr3", "cr2")

	return g
}

func TestFindRelatedDomainsSharedRegistrant(t *testing.T) {
	g := relatedDomainsGraph()

	r, err := FindRelatedDomains(context.Background(), g, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Domains) != 2 {
		t.Fatalf("domains = %+v, want acme.com and acme.net", r.Domains)
	}
	if r.Domains[0].Domain != "acme.com" || r.Domains[1].Domain != "acme.net" {
		t.Errorf("domains not sorted/complete: %+v", r.Domains)
	}
	d := r.Domains[0]
	if d.Confidence != relatedRegistrantConfidence || len(d.Signals) == 0 || len(d.Witness) != 2 {
		t.Errorf("confidence/signals/witness not attached: %+v", d)
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
