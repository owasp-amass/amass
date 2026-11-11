// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import "testing"

func leiRecord(name, jurisdiction, country, postal string) *LEIRecord {
	var r LEIRecord
	r.ID = name
	r.Attributes.Entity.LegalName.Name = name
	r.Attributes.Entity.Jurisdiction = jurisdiction
	r.Attributes.Entity.LegalAddress = LEIAddress{Country: country, PostalCode: postal}
	r.Attributes.Entity.HeadquartersAddress = LEIAddress{Country: country, PostalCode: postal}
	return &r
}

func evidence(postal []string, countries []string) locEvidence {
	ev := locEvidence{postal: map[string]bool{}, countries: map[string]bool{}}
	for _, p := range postal {
		ev.postal[normPostal(p)] = true
	}
	for _, c := range countries {
		ev.countries[normCountry(c)] = true
	}
	return ev
}

func TestChooseLEIRecord(t *testing.T) {
	cases := []struct {
		name   string
		brands []string
		ev     locEvidence
		cands  []leiCandidate
		want   string
	}{
		{
			// Same name, different country: different companies.
			name:   "Stripe, LLC in the US is not STRIPE in Belgium",
			brands: []string{"stripe"},
			ev:     evidence(nil, []string{"US"}),
			cands:  []leiCandidate{{name: "stripe", rec: leiRecord("STRIPE", "BE", "BE", "1000"), exact: true, sim: 1, unique: true}},
		},
		{
			name:   "Apple Inc. in the US is not APPLE 12 in France",
			brands: []string{"apple"},
			ev:     evidence(nil, []string{"US"}),
			cands:  []leiCandidate{{name: "apple 12", rec: leiRecord("APPLE 12", "FR", "FR", "75008"), sim: 0.9, unique: true}},
		},
		{
			name:   "a subsidiary's name is not the organization's",
			brands: []string{"cisco systems"},
			ev:     evidence(nil, []string{"US"}),
			cands: []leiCandidate{{name: "cisco systems france", rec: leiRecord("CISCO SYSTEMS FRANCE", "FR", "FR", "92130"),
				sim: 0.9, unique: true}},
		},
		{
			name:   "a name alone, with no location evidence, is not enough",
			brands: []string{"stripe"},
			ev:     evidence(nil, nil),
			cands:  []leiCandidate{{name: "stripe", rec: leiRecord("STRIPE", "BE", "BE", "1000"), exact: true, sim: 1, unique: true}},
		},
		{
			name:   "the same brand in the same country is accepted",
			brands: []string{"digicert"},
			ev:     evidence(nil, []string{"US"}),
			cands: []leiCandidate{{name: "digicert, inc.", rec: leiRecord("DIGICERT, INC.", "US-UT", "US", "84043"),
				sim: 0.9, unique: true}},
			want: "DIGICERT, INC.",
		},
		{
			name:   "a postal code match is accepted",
			brands: []string{"colgate university"},
			ev:     evidence([]string{"13346"}, []string{"US"}),
			cands: []leiCandidate{{name: "colgate university", rec: leiRecord("Colgate University", "US-NY", "US", "13346"),
				exact: true, sim: 1, unique: true}},
			want: "Colgate University",
		},
		{
			name:   "of two same-named records the one in the organization's country wins",
			brands: []string{"stripe"},
			ev:     evidence(nil, []string{"United States"}),
			cands: []leiCandidate{
				{name: "stripe", rec: leiRecord("STRIPE", "BE", "BE", "1000"), exact: true, sim: 1},
				{name: "stripe, inc.", rec: leiRecord("STRIPE, INC.", "US-DE", "US", "94080"), sim: 0.9},
			},
			want: "STRIPE, INC.",
		},
		{
			name:   "a postal match does not override a country conflict",
			brands: []string{"example"},
			ev:     evidence([]string{"1000"}, []string{"US"}),
			cands:  []leiCandidate{{name: "example", rec: leiRecord("EXAMPLE", "BE", "BE", "1000"), exact: true, sim: 1, unique: true}},
		},
	}
	for _, c := range cases {
		rec, conf := chooseLEIRecord(c.brands, c.ev, c.cands)
		got := ""
		if rec != nil {
			got = rec.Attributes.Entity.LegalName.Name
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
		if rec != nil && (conf <= 0 || conf > maxMatchScore) {
			t.Errorf("%s: confidence %d out of range", c.name, conf)
		}
	}
}

func TestBrandForm(t *testing.T) {
	for in, want := range map[string]string{
		"DigiCert, Inc.":            "digicert",
		"Google Trust Services LLC": "google trust services",
		"stripe":                    "stripe",
		"APPLE 12":                  "apple 12",
	} {
		if got := brandForm(in); got != want {
			t.Errorf("brandForm(%q) = %q, want %q", in, got, want)
		}
	}
}
