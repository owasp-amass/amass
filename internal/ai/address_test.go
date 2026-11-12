// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "testing"

// The addresses are the ones stored for UAlbany, Johns Hopkins, Purdue and
// Clarkson on 11 Nov 2026.
func TestAddressKey(t *testing.T) {
	same := [][2]string{
		{"1400 washington ave room itb102 albany ny 12222 united states", "1400 washington av, albany, ny 12222-1000, usa"},
		{"johns hopkins university 5801 smith avenue baltimore md 21209 us",
			"5801 smith ave, davis bldg., suite 3110b, baltimore, md 21209, usa"},
		{"purdue university 191 north university street, telecommunications building, west lafayette, in 47907-2068, usa",
			"purdue information technology 191 n. university st. west lafayette in 47907 united states"},
		{"8 clarkson ave, box 5585 potsdam new york 13699 us", "8 clarkson ave\r box 5585 potsdam ny 13676 united states"},
	}
	for _, p := range same {
		a, b := addressKey(p[0], ""), addressKey(p[1], "")
		if a == "" || a != b {
			t.Errorf("want one key:\n  %q -> %q\n  %q -> %q", p[0], a, p[1], b)
		}
	}

	different := [][2]string{
		{"3400 north charles street garland hall, suite 020 baltimore md 21218 united states",
			"600 north wolfe street baltimore md 21205 united states"},
		{"191 n. university st. west lafayette in 47907", "155 s. grant street west lafayette in 47907-2114"},
		{"1400 washington ave albany ny 12222", "1400 washington ave rensselaer ny 12144"},
	}
	for _, p := range different {
		if a, b := addressKey(p[0], ""), addressKey(p[1], ""); a != "" && a == b {
			t.Errorf("distinct addresses share key %q:\n  %q\n  %q", a, p[0], p[1])
		}
	}

	for _, s := range []string{
		"office of information technology, box 5585, potsdam, ny 13699-5585, usa",
		"university at albany albany new york us",
		"the johns hopkins university baltimore maryland us",
		"",
	} {
		if k := addressKey(s, ""); k != "" {
			t.Errorf("%q has no street address but got key %q", s, k)
		}
	}

	if k := addressKey("10 downing street london", "SW1A 2AA"); k != "10 downing st|sw1" {
		t.Errorf("postal code from the parsed field: %q", k)
	}
}
