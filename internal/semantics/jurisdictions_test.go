// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestJurisdictionCode(t *testing.T) {
	cases := map[string]string{
		"Delaware":          "US-DE",
		"State of Delaware": "US-DE",
		"NEW YORK":          "US-NY",
		"Ontario":           "CA-ON",
		"England and Wales": "GB",
		"England & Wales":   "GB",
		"U.K.":              "GB",
		"Ireland":           "",
		"Atlantis":          "",
		"Georgia":           "US-GA",
	}
	for in, want := range cases {
		if got := JurisdictionCode(in); got != want {
			t.Errorf("JurisdictionCode(%q) = %q, want %q", in, got, want)
		}
	}
}
