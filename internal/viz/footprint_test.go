// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func TestFootprintDrawings(t *testing.T) {
	g := graphtest.ServicesFixture()
	catalog := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
	report, err := lens.SearchControlled(context.Background(), g, catalog, g.Assets["colgate.edu"], nil, 100)
	if err != nil {
		t.Fatal(err)
	}

	nodes, edges := FootprintGraph(report)
	if len(nodes) < 3 || len(edges) < 2 || nodes[0].Label != "colgate.edu" {
		t.Fatalf("nodes %+v edges %+v", nodes, edges)
	}
	for _, e := range edges {
		if e.From >= len(nodes) || e.To >= len(nodes) {
			t.Fatalf("edge out of range: %+v", e)
		}
	}

	summary := MermaidSummary(nodes, edges)
	if !strings.HasPrefix(summary, "flowchart LR\n") || !strings.Contains(summary, "FQDN (") ||
		!strings.Contains(summary, `-->|"`) {
		t.Errorf("summary:\n%s", summary)
	}
	if detail := MermaidDetail(nodes, edges, 1000); !strings.Contains(detail, "FQDN: colgate.edu") {
		t.Errorf("detail:\n%s", detail)
	}
	if MermaidDetail(nodes, edges, 1) != "" {
		t.Error("a large graph was drawn node by node")
	}

	var d3, gexf bytes.Buffer
	if err := WriteD3Data(&d3, nodes, edges); err != nil || !strings.Contains(d3.String(), "colgate.edu") {
		t.Errorf("d3: %v", err)
	}
	if err := WriteGEXFData(&gexf, nodes, edges); err != nil || !strings.Contains(gexf.String(), "<gexf") {
		t.Errorf("gexf: %v", err)
	}
}

// Labels cannot break out of a Mermaid diagram.
func TestMermaidLabelsAreSafe(t *testing.T) {
	nodes := []Node{
		{ID: 0, Type: "FQDN", Label: `x"] --> evil["<script>`},
		{ID: 1, Type: "IPAddress", Label: "1.2.3.4"},
	}
	edges := []Edge{{From: 0, To: 1, Label: `a"|b`}}
	for _, out := range []string{MermaidSummary(nodes, edges), MermaidDetail(nodes, edges, 10)} {
		if strings.Contains(out, "<script>") || strings.Contains(out, `a"|b`) || strings.Count(out, "-->") != 1 {
			t.Errorf("unsafe diagram:\n%s", out)
		}
	}
}
