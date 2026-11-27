// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"strings"
	"testing"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/owasp-amass/open-asset-model/contact"
)

func TestContactOrganization(t *testing.T) {
	// The EDUCAUSE admin contact for sunyit.edu: the person, then the
	// department, then the street address.
	edu := &whoisparser.Contact{Name: "Jane Doe", Organization: "Information Technology Services",
		Street: "100 Seymour Road", City: "Utica", Province: "NY", PostalCode: "13502", Country: "US"}
	unavailable := func(string) *contact.StreetAddress { return nil }
	building := func(addr string) *contact.StreetAddress {
		return &contact.StreetAddress{Building: strings.ToLower("Information Technology Services")}
	}
	street := func(addr string) *contact.StreetAddress {
		return &contact.StreetAddress{Building: "", StreetName: "seymour road"}
	}

	for name, tc := range map[string]struct {
		contact  *whoisparser.Contact
		parse    func(string) *contact.StreetAddress
		org      string
		person   bool
		addrHead string
	}{
		"address parser unavailable":   {edu, unavailable, "Information Technology Services", true, " 100"},
		"organization is the building": {edu, building, "Information Technology Services", true, " 100"},
		"organization field holds the street": {&whoisparser.Contact{Name: "Acme Hosting LLC",
			Organization: "100 Main Street", City: "Springfield", Country: "US"}, street, "Acme Hosting LLC", false,
			"100 Main Street"},
		"no organization": {&whoisparser.Contact{Name: "Jane Doe", Street: "100 Seymour Road"},
			street, "", true, "100"},
	} {
		org, addr, person := contactOrganization(tc.contact, tc.parse)
		if org != tc.org || person != tc.person || !strings.HasPrefix(strings.TrimSpace(addr),
			strings.TrimSpace(tc.addrHead)) {
			t.Errorf("%s: got (%q, %q, %v), want organization %q, person %v, address starting %q", name, org,
				addr, person, tc.org, tc.person, tc.addrHead)
		}
	}
}
