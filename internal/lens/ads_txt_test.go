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

// A domain whose ads.txt lists the organization's DIRECT account is strong
// evidence, the seller domain sellers.json gives is supporting, and an
// intermediary's account gives nothing; the owner domain the organization's
// ads.txt names, and a site whose ads.txt names the organization as its
// owner, are supporting.
func TestAdsSellerPivot(t *testing.T) {
	g := graphtest.PlannedGraph{FakeGraph: graphtest.FakeGraph{Assets: map[string]graph.Asset{},
		EvidenceByID: map[string][]graph.Evidence{}}}
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	adsFile := func(id, host string) {
		raw := "https://" + host + "/ads.txt"
		add(id, "URL", raw, map[string]any{"url": raw, "host": host, "path": "/ads.txt"})
		add(host, "FQDN", host, map[string]any{"name": host})
		link(id, "domain", host)
	}
	ident := func(id, value string) {
		add(id, "Identifier", "ads_seller:"+value, map[string]any{"unique_id": "ads_seller:" + value, "id": value,
			"id_type": "ads_seller"})
	}

	adsFile("own", "acme.com")
	adsFile("sib", "acme-games.net")
	adsFile("other", "unrelated.org")
	ident("pub", "google.com:pub-1")
	ident("house", "rubiconproject.com:5678")
	link("own", "fingerprint", "pub")
	link("sib", "fingerprint", "pub")
	link("own", "fingerprint", "house")
	link("other", "fingerprint", "house")
	// the seller Accounts sellers.json lists, with the publisher's domain
	add("acct-pub", "Account", "google.com:pub-1", map[string]any{"unique_id": "google.com:pub-1",
		"account_type": "ads_seller", "username": "pub-1"})
	add("acct-house", "Account", "rubiconproject.com:5678", map[string]any{"unique_id": "rubiconproject.com:5678",
		"account_type": "ads_seller", "username": "5678"})
	link("acct-pub", "id", "pub")
	link("acct-house", "id", "house")
	g.EvidenceByID["acct-pub"] = []graph.Evidence{graphtest.SimpleProp(adsPropSellerType, "PUBLISHER")}
	g.EvidenceByID["acct-house"] = []graph.Evidence{graphtest.SimpleProp(adsPropSellerType, "INTERMEDIARY")}
	add("cr-pub", "ContactRecord", "https://google.com/sellers.json#pub-1",
		map[string]any{"discovered_at": "https://google.com/sellers.json#pub-1"})
	add("acme-corp.com", "FQDN", "acme-corp.com", map[string]any{"name": "acme-corp.com"})
	link("acct-pub", "contact", "cr-pub")
	link("cr-pub", "fqdn", "acme-corp.com")
	add("cr-house", "ContactRecord", "https://rubiconproject.com/sellers.json#5678",
		map[string]any{"discovered_at": "https://rubiconproject.com/sellers.json#5678"})
	add("saleshouse.com", "FQDN", "saleshouse.com", map[string]any{"name": "saleshouse.com"})
	link("acct-house", "contact", "cr-house")
	link("cr-house", "fqdn", "saleshouse.com")
	// the organization's ads.txt names its owner's domain
	add("cr-own", "ContactRecord", "https://acme.com/ads.txt", map[string]any{"discovered_at": "https://acme.com/ads.txt"})
	add("acme-holdings.com", "FQDN", "acme-holdings.com", map[string]any{"name": "acme-holdings.com"})
	link("own", "contact", "cr-own")
	link("cr-own", "fqdn", "acme-holdings.com")
	// another site's ads.txt names the organization's domain as its owner's
	adsFile("brand", "acme-brand.io")
	add("cr-brand", "ContactRecord", "https://acme-brand.io/ads.txt",
		map[string]any{"discovered_at": "https://acme-brand.io/ads.txt"})
	link("brand", "contact", "cr-brand")
	link("cr-brand", "fqdn", "acme.com")

	got := map[string]string{}
	adsSellerPivot(context.Background(), g, []string{"acme.com"}, []string{"acme.com"},
		nil,
		func(apex, sig, _ string, _ ...graph.WitnessEdge) {
			got[apex] = sig
		})

	want := map[string]string{"acme-games.net": SigSharedAdsSeller, "acme-corp.com": SigAdsSellerDomain,
		"acme-holdings.com": SigAdsOwnerDomain, "acme-brand.io": SigAdsOwnedBy}
	if len(got) != len(want) {
		t.Fatalf("pivot = %v, want %v", got, want)
	}
	for apex, sig := range want {
		if got[apex] != sig {
			t.Errorf("%s: %q, want %q", apex, got[apex], sig)
		}
	}
}
