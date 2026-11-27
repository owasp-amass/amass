// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"testing"
)

// The addresses keep the shapes of ones stored for four universities on 11 Nov
// 2026, with made-up streets, cities and postal codes.
func TestAddressKey(t *testing.T) {
	same := [][2]string{
		{"1400 example ave room itb102 utica ny 13502 united states", "1400 example av, utica, ny 13502-1000, usa"},
		{"utica university 5801 sample avenue utica ny 13501 us",
			"5801 sample ave, davis bldg., suite 3110b, utica, ny 13501, usa"},
		{"suny polytechnic institute 191 north university street, telecommunications building, marcy, ny 13403-2068, usa",
			"suny poly information technology 191 n. university st. marcy ny 13403 united states"},
		{"8 sample ave, box 5585 rome new york 13440 us", "8 sample ave\r box 5585 rome ny 13441 united states"},
	}
	for _, p := range same {
		a, b := addressKey(p[0], ""), addressKey(p[1], "")
		if a == "" || a != b {
			t.Errorf("want one key:\n  %q -> %q\n  %q -> %q", p[0], a, p[1], b)
		}
	}

	different := [][2]string{
		{"3400 north sample street garland hall, suite 020 utica ny 13501 united states",
			"600 north example street utica ny 13502 united states"},
		{"191 n. university st. marcy ny 13403", "155 s. grant street marcy ny 13403-2114"},
		{"1400 example ave utica ny 13502", "1400 example ave rome ny 13440"},
	}
	for _, p := range different {
		if a, b := addressKey(p[0], ""), addressKey(p[1], ""); a != "" && a == b {
			t.Errorf("distinct addresses share key %q:\n  %q\n  %q", a, p[0], p[1])
		}
	}

	for _, s := range []string{
		"office of information technology, box 5585, rome, ny 13440-5585, usa",
		"utica university utica new york us",
		"the state university of new york albany new york us",
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
