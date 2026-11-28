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

// A code-host organization tied to one of the organization's domains names
// other domains as websites: each is supporting, and shared platforms and
// the organization's own domains give nothing.
func TestCodeHostPivot(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(id, from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: id, FromID: from, ToID: to, Label: label, Type: "SimpleRelation"})
	}
	url := func(id, host string) { add(id, "URL", map[string]any{"url": "https://" + host + "/", "host": host}) }

	add("acme.com", "FQDN", map[string]any{"name": "acme.com"})
	add("gh", "Account", map[string]any{"unique_id": "github:acme", "account_type": "code_host_organization"})
	url("u-docs", "docs.acme-dev.io")
	url("u-own", "www.acme.com")
	url("u-pages", "acme.github.io")
	link("t1", "gh", "namespace_domain", "acme.com")
	link("w1", "gh", "website", "u-docs")
	link("w2", "gh", "website", "u-own")
	link("w3", "gh", "website", "u-pages")

	got := map[string]string{}
	packagePivot(context.Background(), g, []string{"acme.com"}, []string{"acme.com"},
		func(apex, sig, _ string, w ...graph.WitnessEdge) {
			got[apex] = sig
			if len(w) != 2 {
				t.Errorf("%s: %d witness edges, want 2", apex, len(w))
			}
		})
	if len(got) != 1 || got["acme-dev.io"] != SigCodeHostWebsite {
		t.Fatalf("pivot = %v", got)
	}
	if _, strong := HorizontalScore([]string{SigCodeHostWebsite}, nil); strong {
		t.Error("the code-host website signal is strong")
	}
}
