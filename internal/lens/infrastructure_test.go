// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
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
	// The AS that AutnumRecord asr1 registers, and a prefix it announces: a
	// supporting (announced-only) netblock. AutonomousSystem --registration-->
	// AutnumRecord, and AutonomousSystem --announces--> Netblock.
	g.Assets["as1"] = graph.Asset{ID: "as1", Type: "AutonomousSystem", Key: "64500",
		Content: map[string]any{"number": "64500"}}
	g.Assets["nb1"] = graph.Asset{ID: "nb1", Type: "Netblock", Key: "203.0.113.0/24",
		Content: map[string]any{"cidr": "203.0.113.0/24"}}

	link("cr1", "acme", "organization")
	link("ipr1", "cr1", "registrant")
	link("asr1", "cr1", "registrant")
	link("as1", "asr1", "registration")
	link("as1", "nb1", "announces")

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

	// The organization's AS announces only this prefix: an enterprise
	// network, so its announcement is the strong small-AS signal.
	ann, ok := got["Netblock 203.0.113.0/24"]
	if !ok || ann.Confidence != InfrastructureConfidence(SigSmallASNAnnounced) {
		t.Errorf("announced netblock should surface at the small-AS confidence: %+v", r.Assets)
	}

	// The two RIR-registered assets and the small AS's netblock expand.
	expand, review := InfrastructureExpansion(r)
	if len(expand) != 3 || len(review) != 0 {
		t.Errorf("expand %+v, review %+v: want all three to expand", expand, review)
	}
}

// An AS that announces many prefixes may be carrying others' routes, so its
// announcements are the supporting signal and need review.
func TestFindRelatedInfrastructureLargeAS(t *testing.T) {
	g := relatedInfraGraph()
	for i := 0; i <= asnSmallNetblocks; i++ {
		id := fmt.Sprintf("nb-many-%d", i)
		cidr := fmt.Sprintf("198.19.%d.0/24", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "Netblock", Key: cidr, Content: map[string]any{"cidr": cidr}}
		g.Links = append(g.Links, graph.Relation{ID: "ann" + id, FromID: "as1", ToID: id, Label: "announces",
			Type: "SimpleRelation"})
	}
	r, err := FindRelatedInfrastructure(context.Background(), g, "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Assets {
		if a.Asset == "203.0.113.0/24" && a.Confidence != InfrastructureConfidence(SigASNAnnouncedNetblock) {
			t.Errorf("a large AS's netblock %+v should be the supporting signal", a)
		}
	}
	_, review := InfrastructureExpansion(r)
	if len(review) != asnSmallNetblocks+2 {
		t.Errorf("want every announced-only netblock to need review, got %d", len(review))
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
