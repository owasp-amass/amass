// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"github.com/owasp-amass/amass/v5/internal/graph"
)

// GroupVendorFixture puts OWASP and Utica under one parent. Both use
// EDUCAUSE as registrar; Utica's registration also names OWASP, a
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
	link("parent", "subsidiary", "owasp")
	link("parent", "subsidiary", "utica")
	link("dr-utica", "registrar_contact", "cr-educause")
	add("cr-owasp-reg", "ContactRecord", "https://rdap.example/owasp-reg")
	link("cr-owasp-reg", "organization", "owasp")
	link("dr-utica", "registrar_contact", "cr-owasp-reg")

	return g
}
