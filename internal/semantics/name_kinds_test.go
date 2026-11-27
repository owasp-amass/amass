// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestNameKindOf(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		clues NameClues
		want  NameKind
	}{
		{"John Smith", NameClues{First: "John", Last: "Smith"}, NameKindPerson},
		{"OWASP Foundation", NameClues{First: "OWASP", Last: "University"}, NameKindOrganization},
		{"MarkMonitor, Inc.", NameClues{First: "Inc.", Last: "MarkMonitor"}, NameKindOrganization},
		{"Trustees of OWASP", NameClues{First: "Trustees", Last: "OWASP"}, NameKindOrganization},
		{"Domain Administrator", NameClues{First: "Domain", Last: "Administrator"}, NameKindRole},
		{"Sarah Church", NameClues{First: "Sarah", Last: "Church"}, NameKindUncertain},
		{"Sarah Church", NameClues{First: "Sarah", Last: "Church", Emails: []string{"schurch@example.com"}},
			NameKindPerson},
		// a name that matches the record's organization, or one stored
		{"Taylor Wessing", NameClues{First: "Taylor", Last: "Wessing", OrgNames: []string{"TAYLOR WESSING LLP"}},
			NameKindOrganization},
		{"Morgan Stanley", NameClues{First: "Morgan", Last: "Stanley", StoredOrg: true}, NameKindOrganization},
		// organization and person evidence together
		{"Morgan Stanley", NameClues{First: "Morgan", Last: "Stanley", StoredOrg: true,
			Emails: []string{"morgan.stanley@example.com"}}, NameKindUncertain},
		{"Dr. Morgan Stanley", NameClues{First: "Morgan", Last: "Stanley", StoredOrg: true}, NameKindUncertain},
		{"Microsoft", NameClues{}, NameKindUncertain},
		{"", NameClues{}, NameKindUncertain},
	} {
		if got, why := NameKindOf(tc.raw, tc.clues); got != tc.want {
			t.Errorf("%q %+v: %s %v, want %s", tc.raw, tc.clues, got, why, tc.want)
		}
	}
}
