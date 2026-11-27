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

// The publisher site in a verified Maven group is strong; the other URLs the
// organization's packages name are supporting, and its own domains and
// namespaces not tied to it give nothing.
func TestPackagePivot(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}, EvidenceByID: map[string][]graph.Evidence{}}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(id, from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: id, FromID: from, ToID: to, Label: label, Type: "SimpleRelation"})
	}
	url := func(id, host string) { add(id, "URL", map[string]any{"url": "https://" + host + "/", "host": host}) }

	add("acme.com", "FQDN", map[string]any{"name": "acme.com"})
	add("maven", "Account", map[string]any{"unique_id": "maven:com.acme", "account_type": "package_namespace"})
	add("npm", "Account", map[string]any{"unique_id": "npm:@acme", "account_type": "package_namespace"})
	add("core", "Product", map[string]any{"unique_id": "pkg:maven/com.acme/core"})
	add("widgets", "Product", map[string]any{"unique_id": "pkg:npm/%40acme/widgets"})
	url("u-corp", "www.acme-corp.com")
	url("u-docs", "docs.acme-dev.io")
	url("u-own", "api.acme.com")
	url("u-npm", "widgets.acme.app")
	url("u-gh", "github.com")
	link("t1", "maven", "namespace_domain", "acme.com")
	link("t2", "npm", "namespace_domain", "acme.com")
	link("p1", "maven", "package", "core")
	link("p2", "npm", "package", "widgets")
	link("w1", "core", "website", "u-corp")
	link("w2", "core", "website", "u-docs")
	link("w3", "core", "website", "u-own")
	link("w4", "widgets", "website", "u-npm")
	link("w5", "widgets", "website", "u-gh")
	role := func(edge, r string) {
		g.EvidenceByID[edge] = []graph.Evidence{graphtest.SimpleProp(packagePropURLRole, r)}
	}
	role("w1", packageRoleOrg)
	role("w2", "project")
	role("w4", packageRoleOrg) // an npm package has no verified group, so this stays supporting

	got := map[string]string{}
	packagePivot(context.Background(), g, []string{"acme.com"}, []string{"acme.com"},
		func(apex, sig, _ string, w ...graph.WitnessEdge) {
			got[apex] = sig
			if len(w) != 3 {
				t.Errorf("%s: %d witness edges, want 3", apex, len(w))
			}
		})

	want := map[string]string{"acme-corp.com": SigPackageOrganization, "acme-dev.io": SigPackageWebsite,
		"acme.app": SigPackageWebsite}
	if len(got) != len(want) {
		t.Fatalf("pivot = %v, want %v", got, want)
	}
	for apex, sig := range want {
		if got[apex] != sig {
			t.Errorf("%s: %q, want %q", apex, got[apex], sig)
		}
	}
	if _, strong := HorizontalScore([]string{SigPackageOrganization}, nil); !strong {
		t.Error("the publisher-site signal is not strong")
	}
	if _, strong := HorizontalScore([]string{SigPackageWebsite}, nil); strong {
		t.Error("the package-website signal is strong")
	}
}

// A URL on a shared platform is the organization's, but control stops there:
// the platform's domain and its other hosts never join the footprint, while a
// URL on a domain of the organization's own still brings in that domain.
func TestFootprintStopsAtSharedPlatforms(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	add("acme", "Organization", map[string]any{"name": "Acme"})
	add("u-repo", "URL", map[string]any{"url": "https://github.com/acme", "host": "github.com"})
	add("github.com", "FQDN", map[string]any{"name": "github.com"})
	add("gist.github.com", "FQDN", map[string]any{"name": "gist.github.com"})
	add("u-site", "URL", map[string]any{"url": "https://acme-news.org/", "host": "acme-news.org"})
	add("acme-news.org", "FQDN", map[string]any{"name": "acme-news.org"})
	link("acme", "website", "u-repo")
	link("u-repo", "domain", "github.com")
	link("github.com", "node", "gist.github.com")
	link("acme", "website", "u-site")
	link("u-site", "domain", "acme-news.org")

	w := newLensWalker(context.Background(), g, g, graph.MeaningsOf(graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}),
		graphtest.TestOAMCatalog.Relations(), g.Assets["acme"], &ThirdPartyReport{FootprintTypes: map[string]int{}})
	owned, _, err := w.controlledFootprint([]graph.Asset{g.Assets["acme"]})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"u-repo": true, "u-site": true, "acme-news.org": true,
		"github.com": false, "gist.github.com": false} {
		if _, got := owned[id]; got != want {
			t.Errorf("%s in the footprint: %v, want %v", id, got, want)
		}
	}
}

func TestPublisherHost(t *testing.T) {
	for host, want := range map[string]bool{"www.acme-corp.com": true, "github.com": false, "www.npmjs.com": false,
		"acme.github.io": false, "acme.s3.amazonaws.com": false} {
		if got := publisherHost(host); got != want {
			t.Errorf("publisherHost(%q) = %v, want %v", host, got, want)
		}
	}
}
