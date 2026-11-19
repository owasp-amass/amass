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

func relatedInfraGraph() graphtest.FakeGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	g.Assets["acme"] = graph.Asset{ID: "acme", Type: "Organization", Key: "Acme:1",
		Content: map[string]any{"name": "Acme Corporation"}}
	g.Assets["cr1"] = graph.Asset{ID: "cr1", Type: "ContactRecord", Key: "cr1", Content: map[string]any{}}
	g.Assets["ipr1"] = graph.Asset{ID: "ipr1", Type: "IPNetRecord", Key: "ipr1",
		Content: map[string]any{"cidr": "192.0.2.0/24"}}
	g.Assets["asr1"] = graph.Asset{ID: "asr1", Type: "AutnumRecord", Key: "asr1",
		Content: map[string]any{"number": "64500"}}
	link := func(from, to, label string) {
		g.Links = append(g.Links, graph.Relation{ID: label + from + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	link("cr1", "acme", "organization")
	link("ipr1", "cr1", "registrant")
	link("asr1", "cr1", "registrant")

	// A privacy-proxy organization with its own netblock registration: never
	// correlated on.
	g.Assets["proxy"] = graph.Asset{ID: "proxy", Type: "Organization", Key: "proxy:1",
		Content: map[string]any{"name": "Domains By Proxy, LLC"}}
	g.Assets["cr2"] = graph.Asset{ID: "cr2", Type: "ContactRecord", Key: "cr2", Content: map[string]any{}}
	g.Assets["ipr2"] = graph.Asset{ID: "ipr2", Type: "IPNetRecord", Key: "ipr2",
		Content: map[string]any{"cidr": "198.51.100.0/24"}}
	link("cr2", "proxy", "organization")
	link("ipr2", "cr2", "registrant")

	return g
}

func TestFindRelatedInfrastructure(t *testing.T) {
	g := relatedInfraGraph()

	r, err := FindRelatedInfrastructure(context.Background(), g, "acme")
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]InfrastructureAsset{}
	for _, a := range r.Assets {
		got[a.AssetType+" "+a.Asset] = a
	}
	nb, ok := got["Netblock 192.0.2.0/24"]
	if !ok || nb.Confidence != InfrastructureConfidence(SigIPNetRegistrantOrg) || len(nb.Witness) == 0 {
		t.Errorf("netblock from the IPNetRecord registrant should be present with witness: %+v", r.Assets)
	}
	as, ok := got["AutonomousSystem 64500"]
	if !ok || as.Confidence != InfrastructureConfidence(SigASNRegistrantOrg) {
		t.Errorf("AS from the AutnumRecord registrant should be present: %+v", r.Assets)
	}

	// Both are strong signals, so both are eligible to expand.
	expand, review := InfrastructureExpansion(r)
	if len(expand) != 2 || len(review) != 0 {
		t.Errorf("both registrant-backed assets should be in the expand set: expand=%+v review=%+v", expand, review)
	}
}

func TestFindRelatedInfrastructureSkipsPrivacyProxy(t *testing.T) {
	g := relatedInfraGraph()

	r, err := FindRelatedInfrastructure(context.Background(), g, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 0 {
		t.Errorf("a privacy-proxy organization must not be correlated on, got %+v", r.Assets)
	}
}
