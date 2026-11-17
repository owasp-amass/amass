// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import "testing"

func TestRankOrganizations(t *testing.T) {
	cands := []OrgCandidate{
		{ID: "1", Name: "SUNY Polytechnic Institute", Domains: 2},
		{ID: "2", Name: "State University of New York", Domains: 9},
		{ID: "3", Name: "Acme Corporation", LegalName: "Acme Corporation, Inc.", Domains: 1},
		{ID: "4", Name: "Globex LLC", Domains: 0},
		{ID: "5", Name: "Initech", Domains: 3},
	}

	cases := []struct {
		name     string
		query    string
		wantTop  string // ID expected first, "" if no match expected
		wantWhy  string
		excludes string // ID that must not appear
	}{
		{name: "exact", query: "SUNY Polytechnic Institute", wantTop: "1", wantWhy: "exact name"},
		{name: "left out part", query: "SUNY Poly", wantTop: "1", wantWhy: "matches your terms"},
		{name: "misspelled word", query: "SUNY Polytecnic Institute", wantTop: "1"},
		{name: "legal form omitted", query: "Acme", wantTop: "3", wantWhy: "exact name"},
		{name: "legal form differs", query: "Globex Limited", wantTop: "4", wantWhy: "exact name"},
		{name: "misspelled single", query: "Initek", wantTop: "5", wantWhy: "similar spelling"},
		{name: "unrelated", query: "Umbrella Pharmaceuticals", wantTop: ""},
	}
	for _, c := range cases {
		got := RankOrganizations(c.query, cands, 5)
		if c.wantTop == "" {
			if len(got) != 0 {
				t.Errorf("%s: expected no matches, got %+v", c.name, got)
			}
			continue
		}
		if len(got) == 0 || got[0].ID != c.wantTop {
			t.Errorf("%s: top = %+v, want ID %s", c.name, got, c.wantTop)
			continue
		}
		if c.wantWhy != "" && got[0].Why != c.wantWhy {
			t.Errorf("%s: why = %q, want %q", c.name, got[0].Why, c.wantWhy)
		}
	}
}

func TestRankOrganizationsTieBreakPrefersSeedable(t *testing.T) {
	// Two equally-named orgs: the one controlling domains (seedable) comes first.
	cands := []OrgCandidate{
		{ID: "empty", Name: "Example Corp", Domains: 0},
		{ID: "seedable", Name: "Example Corp", Domains: 4},
	}
	got := RankOrganizations("Example Corp", cands, 5)
	if len(got) < 2 || got[0].ID != "seedable" {
		t.Errorf("seedable org should rank first: %+v", got)
	}
}

func TestRankOrganizationsLimit(t *testing.T) {
	cands := []OrgCandidate{
		{ID: "1", Name: "Data Systems One"},
		{ID: "2", Name: "Data Systems Two"},
		{ID: "3", Name: "Data Systems Three"},
	}
	if got := RankOrganizations("Data Systems", cands, 2); len(got) != 2 {
		t.Errorf("limit not applied: got %d", len(got))
	}
}
