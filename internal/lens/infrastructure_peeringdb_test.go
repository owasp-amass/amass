// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// An AS whose PeeringDB operator record names the organization is its own,
// and the netblocks it announces are scored like a registered AS's.
func TestFindRelatedInfrastructurePeeringDB(t *testing.T) {
	g := relatedInfraGraph()
	g.Assets["pdb"] = graph.Asset{ID: "pdb", Type: "ContactRecord", Key: "https://www.peeringdb.com/org/2",
		Content: map[string]any{"discovered_at": "https://www.peeringdb.com/org/2"}}
	g.Assets["as2"] = graph.Asset{ID: "as2", Type: "AutonomousSystem", Key: "64501",
		Content: map[string]any{"number": "64501"}}
	g.Assets["nb2"] = graph.Asset{ID: "nb2", Type: "Netblock", Key: "198.51.100.128/25",
		Content: map[string]any{"cidr": "198.51.100.128/25"}}
	for _, l := range [][3]string{{"pdb", "acme", "organization"}, {"as2", "pdb", "contact"},
		{"as2", "nb2", "announces"}} {
		g.Links = append(g.Links, graph.Relation{ID: l[2] + l[0] + l[1], FromID: l[0], ToID: l[1], Label: l[2],
			Type: "SimpleRelation"})
	}

	r, err := FindRelatedInfrastructure(context.Background(), g, "acme")
	if err != nil {
		t.Fatal(err)
	}
	signals := map[string][]string{}
	for _, a := range r.Assets {
		signals[a.AssetType+" "+a.Asset] = a.SignalIDs
	}
	if !slices.Contains(signals["AutonomousSystem 64501"], SigASNPeeringDBOrg) {
		t.Errorf("the PeeringDB AS: %v", signals)
	}
	if !slices.Contains(signals["Netblock 198.51.100.128/25"], SigSmallASNAnnounced) {
		t.Errorf("the netblock it announces: %v", signals)
	}
	// the registered AS is unchanged
	if !slices.Contains(signals["AutonomousSystem 64500"], SigASNRegistrantOrg) {
		t.Errorf("the registered AS: %v", signals)
	}
}
