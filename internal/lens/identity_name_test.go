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
		// the single-letter legal-form tokens S.A.).
		{"acronym owasp", "open worldwide application security project s a", []string{"owasp"}, true},
		// Country/region subsidiary suffix.
		{"region france", "cisco systems france", []string{"cisco systems"}, true},
		{"region germany + legal form", "salesforce.com germany gmbh", []string{"salesforce.com"}, true},
		// Division-word suffix.
		{"division group", "cogent communications group, llc", []string{"cogent communications"}, true},
		// Exact brand match (legal form stripped).
		{"exact brand", "microsoft corporation", []string{"microsoft"}, true},
		// Institution-type rename: Utica College became Utica University, so the
		// GLEIF legal name is not a wrong identity.
		{"institution college/university", "utica college", []string{"utica university"}, true},
		{"institution university/college", "utica university", []string{"utica college"}, true},
		{"institution institute/university", "suny polytechnic institute", []string{"suny polytechnic university"}, true},
		// Governance/legal-entity wrapper: "The Trustees of OWASP Foundation" is
		// a legal name for "OWASP Foundation", not a wrong identity (semantics.OrgNameKey
		// strips the wrapper so the brands match).
		{"governance prefix trustees", "the trustees of owasp foundation", []string{"owasp foundation"}, true},
		{"governance prefix the regents", "the regents of the university of michigan", []string{"university of michigan"}, true},
		// Empty legal name has nothing to disagree with.
		{"empty legal", "", []string{"amazon"}, true},

		// Genuine mismatches must still be flagged.
		{"typo amazone", "amazone", []string{"amazon"}, false},
		{"unrelated mol corporation", "mol corporation", []string{"microsoft"}, false},
		// A suffix that is not purely region/division tokens is not a subsidiary.
		{"non-region suffix", "acme france bakery", []string{"acme"}, false},
		// A type swap with no shared token is still a mismatch, not a rename.
		{"different brand same type word", "utica college", []string{"suny college"}, false},
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
		{"acronym is not subsidiary", "open worldwide application security project s a", []string{"owasp"}, true, false},
		{"institution rename is not subsidiary", "utica college", []string{"utica university"}, true, false},
		{"governance prefix is not subsidiary", "the trustees of owasp foundation", []string{"owasp foundation"}, true, false},
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
