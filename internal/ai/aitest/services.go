// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitest

import (
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

// ServicesFixture adds what the HTTP and SSH probes store to the vendor
// fixture: a web service on www.colgate.edu with a server header, an
// expired certificate and a product, and an SSH service on an unusual port
// of portal.colgate.edu presenting a self-issued certificate.
func ServicesFixture() VendorGraph {
	g := VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	port := func(from, to string, n int) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-port-" + to, FromID: from, ToID: to, Label: "port",
			Type: "PortRelation", Content: map[string]any{"port_number": n, "protocol": "TCP"}})
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	add("svc-web", "Service", map[string]any{"unique_id": "svc-web", "service_type": "web-service",
		"attributes": map[string]any{"Server": []any{"nginx/1.18.0"}, "Content-Type": []any{"text/html"}}})
	add("svc-ssh", "Service", map[string]any{"unique_id": "svc-ssh", "service_type": "ssh"})
	add("cert-web", "TLSCertificate", map[string]any{"subject_common_name": "www.colgate.edu",
		"issuer_common_name": "R11", "not_after": "2026-01-01T00:00:00Z"})
	add("cert-ssh", "TLSCertificate", map[string]any{"subject_common_name": "portal.colgate.edu",
		"issuer_common_name": "portal.colgate.edu", "not_after": "2030-01-01T00:00:00Z"})
	add("nginx", "Product", map[string]any{"name": "nginx"})

	port("www.colgate.edu", "svc-web", 443)
	port("colgate.edu", "svc-web", 443)
	port("portal.colgate.edu", "svc-ssh", 2222)
	link("svc-web", "certificate", "cert-web")
	link("svc-ssh", "certificate", "cert-ssh")
	link("svc-web", "product_used", "nginx")

	return g
}
