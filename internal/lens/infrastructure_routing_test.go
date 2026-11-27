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

// routingInfraGraph adds routing security records to the related
// infrastructure fixture: a ROA authorizing the organization's AS for a
// netblock nothing else ties to it, a maintainer that keeps only the
// organization's routes, and a maintainer that also keeps another AS's.
func routingInfraGraph() graphtest.FakeGraph {
	g := relatedInfraGraph()
	g.EvidenceByID = map[string][]graph.Evidence{}
	nb := func(id, cidr string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Netblock", Key: cidr, Content: map[string]any{"cidr": cidr}}
	}
	link := func(from, to, label string) {
		g.Links = append(g.Links, graph.Relation{ID: label + from + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	mnt := func(id string, routes string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Identifier", Key: "irr_maintainer:" + id,
			Content: map[string]any{"unique_id": "irr_maintainer:" + id, "id": id, "id_type": "irr_maintainer"}}
		g.EvidenceByID[id] = []graph.Evidence{graphtest.SimpleProp(propIRRRoutes, routes)}
	}
	// each route netblock names its origin AS
	g.Assets["as-other"] = graph.Asset{ID: "as-other", Type: "AutonomousSystem", Key: "64511",
		Content: map[string]any{"number": "64511"}}

	nb("nb-roa", "198.18.0.0/24")
	link("nb-roa", "as1", "rpki_origin")

	link("nb1", "as1", "irr_origin")

	mnt("RADB:MAINT-ACME", "2")
	link("nb1", "RADB:MAINT-ACME", "irr_maintainer")
	nb("nb-own", "198.18.8.0/24")
	link("nb-own", "RADB:MAINT-ACME", "irr_maintainer")
	link("nb-own", "as1", "irr_origin")

	mnt("RADB:MAINT-HOSTER", "2")
	link("nb1", "RADB:MAINT-HOSTER", "irr_maintainer")
	nb("nb-shared", "198.18.16.0/24")
	link("nb-shared", "RADB:MAINT-HOSTER", "irr_maintainer")
	link("nb-shared", "as-other", "irr_origin")

	mnt("RADB:MAINT-ISP", "5000")
	link("nb1", "RADB:MAINT-ISP", "irr_maintainer")
	nb("nb-isp", "198.18.24.0/24")
	link("nb-isp", "RADB:MAINT-ISP", "irr_maintainer")
	return g
}

func TestRoutingSecuritySignals(t *testing.T) {
	r, err := FindRelatedInfrastructure(context.Background(), routingInfraGraph(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]InfrastructureAsset{}
	for _, a := range r.Assets {
		got[a.Asset] = a
	}

	for cidr, sig := range map[string]string{"198.18.0.0/24": SigROAOwnASN, "198.18.8.0/24": SigIRRMaintainerOwn,
		"198.18.16.0/24": SigSharedIRRMaintainer} {
		a, ok := got[cidr]
		if !ok || len(a.SignalIDs) != 1 || a.SignalIDs[0] != sig {
			t.Errorf("%s: %+v, want %s alone", cidr, a, sig)
		}
	}
	if _, ok := got["198.18.24.0/24"]; ok {
		t.Error("a maintainer keeping thousands of routes related a netblock")
	}

	expand, review := InfrastructureExpansion(r)
	in := func(list []InfrastructureAsset, cidr string) bool {
		for _, a := range list {
			if a.Asset == cidr {
				return true
			}
		}
		return false
	}
	if !in(expand, "198.18.0.0/24") || !in(expand, "198.18.8.0/24") || !in(review, "198.18.16.0/24") {
		t.Errorf("expand %+v, review %+v: the ROA and own maintainer expand, the shared maintainer waits",
			expand, review)
	}
}
