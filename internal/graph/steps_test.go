// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"sort"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// plainGraph hides every reader but graph.Graph, so StepsFrom reads each
// asset's edges.
type plainGraph struct{ graph.Graph }

// A step read follows forward steps from an edge's source and backward ones
// from its destination, each edge once, the same with a StepReader or by
// reading each asset's edges.
func TestStepsFrom(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{
		"org":  {ID: "org", Type: "Organization"},
		"sub":  {ID: "sub", Type: "Organization"},
		"root": {ID: "root", Type: "FQDN"},
		"www":  {ID: "www", Type: "FQDN"},
		"ip":   {ID: "ip", Type: "IPAddress"},
	}, Links: []graph.Relation{
		{ID: "e1", FromID: "org", ToID: "sub", Label: "subsidiary", Type: "SimpleRelation"},
		{ID: "e2", FromID: "root", ToID: "www", Label: "node", Type: "SimpleRelation"},
		{ID: "e3", FromID: "root", ToID: "ip", Label: "dns_record", Type: "BasicDNSRelation"},
	}}
	steps := []graph.Step{
		{FromType: "Organization", Label: "subsidiary", RelationType: "SimpleRelation", ToType: "Organization", Forward: true},
		{FromType: "fqdn", Label: "NODE", RelationType: "simplerelation", ToType: "fqdn", Forward: true},
		{FromType: "FQDN", Label: "dns_record", RelationType: "BasicDNSRelation", ToType: "IPAddress"},
	}

	for name, gr := range map[string]graph.Graph{"step reader": g, "edge reads": plainGraph{g}} {
		ids := func(from ...string) []string {
			edges, err := graph.StepsFrom(context.Background(), gr, from, steps)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			var out []string
			for _, e := range edges {
				out = append(out, e.ID)
			}
			sort.Strings(out)
			return out
		}
		if got := ids("org", "root", "ip"); len(got) != 3 {
			t.Errorf("%s: edges %v, want e1, e2 and e3 once each", name, got)
		}
		if got := ids("sub", "www"); len(got) != 0 {
			t.Errorf("%s: forward steps were followed backward: %v", name, got)
		}
		if got := ids("root"); len(got) != 1 || got[0] != "e2" {
			t.Errorf("%s: a backward step was followed forward: %v", name, got)
		}
	}
}
