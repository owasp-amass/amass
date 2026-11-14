// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitest

import (
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

// groupVendorFixture puts Colgate and Hamilton under one parent. Both use
// EDUCAUSE as registrar; Hamilton's registration also names Colgate, a
// group organization, as a contact.
func GroupVendorFixture() VendorGraph {
	g := VendorFixture()
	add := func(id, typ, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: name, Content: map[string]any{"name": name}}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	add("parent", "Organization", "Central New York Colleges")
	link("parent", "subsidiary", "colgate")
	link("parent", "subsidiary", "hamilton")
	link("dr-hamilton", "registrar_contact", "cr-educause")
	add("cr-colgate-reg", "ContactRecord", "https://rdap.example/colgate-reg")
	link("cr-colgate-reg", "organization", "colgate")
	link("dr-hamilton", "registrar_contact", "cr-colgate-reg")

	return g
}
