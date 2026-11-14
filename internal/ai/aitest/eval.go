// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitest

import (
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

// campusWebFixture adds websites to the campus: the organization's website
// on a CDN and a portal on its own network.
func CampusWebFixture() VendorGraph {
	g := VendorFixture()
	g.Assets["url-www"] = graph.Asset{ID: "url-www", Type: "URL", Key: "https://www.colgate.edu",
		Content: map[string]any{"url": "https://www.colgate.edu"}}
	g.Assets["url-portal"] = graph.Asset{ID: "url-portal", Type: "URL", Key: "https://portal.colgate.edu",
		Content: map[string]any{"url": "https://portal.colgate.edu"}}
	g.Links = append(g.Links,
		graph.Relation{ID: "w1", FromID: "colgate", ToID: "url-www", Label: "website", Type: "SimpleRelation"},
		graph.Relation{ID: "w2", FromID: "url-www", ToID: "www.colgate.edu", Label: "domain", Type: "SimpleRelation"},
		graph.Relation{ID: "w3", FromID: "url-portal", ToID: "portal.colgate.edu", Label: "domain", Type: "SimpleRelation"})
	return g
}

func CampusWeb() (graph.Graph, graph.SchemaCatalog) {
	return CampusWebFixture(), VendorCatalog{TestOAMCatalog}
}
