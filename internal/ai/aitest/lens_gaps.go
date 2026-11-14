// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitest

import (
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

// CampusGapsFixture adds unattributed assets to the campus: a registrant
// contact sharing Colgate's phone and address (identity), a name resolving
// into Colgate's netblock (hosting), a name on Colgate's certificate that
// also resolves there (co-listing and hosting), and a Hamilton College name
// pointing into Colgate's network (controlled elsewhere, not a gap).
func CampusGapsFixture() VendorGraph {
	g := VendorFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }

	add("phone", "Phone", "+1.3152287000", map[string]any{"e164": "+1.3152287000"})
	add("loc", "Location", "13 Oak Drive, Hamilton NY", map[string]any{"address": "13 Oak Drive, Hamilton NY"})
	link("cr-colgate", "phone", "phone", "SimpleRelation")
	link("cr-colgate", "location", "loc", "SimpleRelation")

	add("cr-alt", "ContactRecord", "https://rdap.example/alumni", nil)
	add("dr-alt", "DomainRecord", "colgatealumni.org", map[string]any{"domain": "colgatealumni.org"})
	named("colgatealumni.org", "FQDN", "colgatealumni.org")
	link("cr-alt", "phone", "phone", "SimpleRelation")
	link("cr-alt", "location", "loc", "SimpleRelation")
	link("dr-alt", "registrant_contact", "cr-alt", "SimpleRelation")
	link("colgatealumni.org", "registration", "dr-alt", "SimpleRelation")

	named("raiders.example.net", "FQDN", "raiders.example.net")
	link("raiders.example.net", "dns_record", "ip-own", "BasicDNSRelation")

	named("colgate-events.com", "FQDN", "colgate-events.com")
	link("cert", "san_dns_name", "colgate-events.com", "SimpleRelation")
	link("colgate-events.com", "dns_record", "ip-own", "BasicDNSRelation")

	link("www.hamilton.edu", "dns_record", "ip-own", "BasicDNSRelation")
	return g
}
