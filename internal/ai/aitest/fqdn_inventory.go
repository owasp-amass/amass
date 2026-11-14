// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitest

import (
	"fmt"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

var FQDNInventoryCatalog = PlanCatalog{
	{SourceType: "FQDN", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	{SourceType: "FQDN", Label: "dns_record", RelationType: "BasicDNSRelation", DestinationType: "IPAddress"},
}

// LargeFQDNInventoryFixture models a campus namespace: 150 direct
// subdomains plus 50 under cslab, more than the model-context node,
// per-node and find limits allow.
func LargeFQDNInventoryFixture() PlannedGraph {
	root := graph.Asset{ID: "root", Type: "FQDN", Key: "colgate.edu", Content: map[string]any{"name": "colgate.edu"}}
	g := FakeGraph{Assets: map[string]graph.Asset{"root": root}}
	add := func(id, name, parent string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		g.Links = append(g.Links, graph.Relation{ID: "node-" + id, FromID: parent, ToID: id, Label: "node",
			Type: "SimpleRelation"})
	}

	add("cslab", "cslab.colgate.edu", "root")
	for i := 0; i < 149; i++ {
		add(fmt.Sprintf("host-%03d", i), fmt.Sprintf("host%03d.colgate.edu", i), "root")
	}
	for i := 0; i < 50; i++ {
		add(fmt.Sprintf("lab-%02d", i), fmt.Sprintf("lab%02d.cslab.colgate.edu", i), "cslab")
	}

	return PlannedGraph{FakeGraph: g}
}
