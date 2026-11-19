// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import "testing"

func TestLegalNameAgrees(t *testing.T) {
	cases := []struct {
		name        string
		legal       string
		independent []string
		want        bool
	}{
		// Acronym: the common name is the initials of the legal name (including
		// the single-letter legal-form tokens S.A.B.).
		{"acronym femsa", "fomento economico mexicano s a b de c v", []string{"femsa"}, true},
		// Country/region subsidiary suffix.
		{"region france", "cisco systems france", []string{"cisco systems"}, true},
		{"region germany + legal form", "salesforce.com germany gmbh", []string{"salesforce.com"}, true},
		// Division-word suffix.
		{"division group", "cogent communications group, llc", []string{"cogent communications"}, true},
		// Exact brand match (legal form stripped).
		{"exact brand", "microsoft corporation", []string{"microsoft"}, true},
		// Empty legal name has nothing to disagree with.
		{"empty legal", "", []string{"amazon"}, true},

		// Genuine mismatches must still be flagged.
		{"typo amazone", "amazone", []string{"amazon"}, false},
		{"unrelated mol corporation", "mol corporation", []string{"microsoft"}, false},
		// A suffix that is not purely region/division tokens is not a subsidiary.
		{"non-region suffix", "acme france bakery", []string{"acme"}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := legalNameAgrees(c.legal, c.independent); got != c.want {
				t.Errorf("legalNameAgrees(%q, %v) = %v, want %v", c.legal, c.independent, got, c.want)
			}
		})
	}
}

// Only a subsidiary-suffix agreement explains a foreign jurisdiction; an exact
// or acronym agreement does not, so the jurisdiction-mismatch reason still fires
// for a same-named company registered abroad.
func TestLegalNameAgreementViaSubsidiary(t *testing.T) {
	cases := []struct {
		name           string
		legal          string
		independent    []string
		agrees, viaSub bool
	}{
		{"exact is not subsidiary", "stripe", []string{"Stripe, LLC."}, true, false},
		{"region suffix is subsidiary", "cisco systems france", []string{"cisco systems"}, true, true},
		{"division suffix is subsidiary", "cogent communications group, llc", []string{"cogent communications"}, true, true},
		{"acronym is not subsidiary", "fomento economico mexicano s a b de c v", []string{"femsa"}, true, false},
		{"disagree", "mol corporation", []string{"microsoft"}, false, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agrees, viaSub := legalNameAgreement(c.legal, c.independent)
			if agrees != c.agrees || viaSub != c.viaSub {
				t.Errorf("legalNameAgreement(%q, %v) = (%v, %v), want (%v, %v)",
					c.legal, c.independent, agrees, viaSub, c.agrees, c.viaSub)
			}
		})
	}
}
