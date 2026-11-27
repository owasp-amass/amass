// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"github.com/owasp-amass/amass/v5/internal/graph"
)

// CampusWebFixture adds websites to the campus: the organization's website
// on a CDN and a portal on its own network.
func CampusWebFixture() VendorGraph {
	g := VendorFixture()
	g.Assets["url-www"] = graph.Asset{ID: "url-www", Type: "URL", Key: "https://www.owasp.org",
		Content: map[string]any{"url": "https://www.owasp.org"}}
	g.Assets["url-portal"] = graph.Asset{ID: "url-portal", Type: "URL", Key: "https://portal.owasp.org",
		Content: map[string]any{"url": "https://portal.owasp.org"}}
	g.Links = append(g.Links,
		graph.Relation{ID: "w1", FromID: "owasp", ToID: "url-www", Label: "website", Type: "SimpleRelation"},
		graph.Relation{ID: "w2", FromID: "url-www", ToID: "www.owasp.org", Label: "domain", Type: "SimpleRelation"},
		graph.Relation{ID: "w3", FromID: "url-portal", ToID: "portal.owasp.org", Label: "domain", Type: "SimpleRelation"})
	return g
}

func CampusWeb() (graph.Graph, graph.SchemaCatalog) {
	return CampusWebFixture(), VendorCatalog{TestOAMCatalog}
}
