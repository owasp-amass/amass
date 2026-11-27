// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"github.com/owasp-amass/amass/v5/internal/graph"
)

// CampusGapsFixture adds unattributed assets to the campus: a registrant
// contact sharing OWASP's phone and address (identity), a name resolving
// into OWASP's netblock (hosting), a name on OWASP's certificate that
// also resolves there (co-listing and hosting), and a Utica University name
// pointing into OWASP's network (controlled elsewhere, not a gap).
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

	add("phone", "Phone", "+1.3155557000", map[string]any{"e164": "+1.3155557000"})
	add("loc", "StreetAddress", "100 Main Street, Utica NY", map[string]any{"address": "100 Main Street, Utica NY"})
	link("cr-owasp", "phone", "phone", "SimpleRelation")
	link("cr-owasp", "street_address", "loc", "SimpleRelation")

	add("cr-alt", "ContactRecord", "https://rdap.example/alumni", nil)
	add("dr-alt", "DomainRecord", "owaspalumni.org", map[string]any{"domain": "owaspalumni.org"})
	named("owaspalumni.org", "FQDN", "owaspalumni.org")
	link("cr-alt", "phone", "phone", "SimpleRelation")
	link("cr-alt", "street_address", "loc", "SimpleRelation")
	link("dr-alt", "registrant_contact", "cr-alt", "SimpleRelation")
	link("owaspalumni.org", "registration", "dr-alt", "SimpleRelation")

	named("raiders.example.net", "FQDN", "raiders.example.net")
	link("raiders.example.net", "dns_record", "ip-own", "BasicDNSRelation")

	named("owasp-events.com", "FQDN", "owasp-events.com")
	link("cert", "san_dns_name", "owasp-events.com", "SimpleRelation")
	link("owasp-events.com", "dns_record", "ip-own", "BasicDNSRelation")

	link("www.utica.edu", "dns_record", "ip-own", "BasicDNSRelation")
	return g
}
