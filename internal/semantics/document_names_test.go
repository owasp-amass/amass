// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestMisnamedDocumentName(t *testing.T) {
	for _, tc := range []struct{ typ, name, want string }{
		{"Organization", "Boyd Hall", "a building"},
		{"Organization", "Strebel Student Center", ""},
		{"Organization", "Clery Act", "a law"},
		{"Organization", "Family Educational Rights and Privacy Act", "a law"},
		{"Organization", "Title IX", "a law"},
		{"Organization", "Title IX Office", ""},
		{"Organization", "CS 101", "a course"},
		{"Person", "BIO 210L Lab", "a course"},
		{"Organization", "Utica University", ""},
		{"Organization", "Office of the Registrar", ""},
		{"Person", "Chief Information Officer", "a job title"},
		{"Person", "Dean of Students", "a job title"},
		{"Person", "Director for Admissions", "a job title"},
		{"Person", "Dean Smith", ""},
		{"Person", "John Dean", ""},
		{"Person", "Monty Hall", ""},
		{"Person", "Jude Law", ""},
		{"Person", "Sarah Church", ""},
		{"Product", "Boyd Hall", ""},
		{"Organization", "", ""},
	} {
		if got := MisnamedDocumentName(tc.typ, tc.name); got != tc.want {
			t.Errorf("%s %q = %q, want %q", tc.typ, tc.name, got, tc.want)
		}
	}
}
