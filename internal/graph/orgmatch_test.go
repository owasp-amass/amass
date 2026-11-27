// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeOrgSearch is a minimal OrgSearchGraph: it resolves an exact name and
// lists its organizations for the fuzzy pass.
type fakeOrgSearch struct{ orgs []Asset }

func (f fakeOrgSearch) FindAssets(_ context.Context, kind string, _ time.Time, limit int) ([]Asset, error) {
	if kind != "Organization" {
		return nil, nil
	}
	if limit > 0 && len(f.orgs) > limit {
		return f.orgs[:limit], nil
	}
	return f.orgs, nil
}

func (f fakeOrgSearch) ResolveOrganizations(_ context.Context, q OrganizationQuery, _ int) (OrganizationResolution, error) {
	var cands []OrganizationCandidate
	for _, a := range f.orgs {
		if strings.EqualFold(ContentString(a, "name"), q.Name) {
			cands = append(cands, OrganizationCandidate{Asset: a})
		}
	}
	st := "not_found"
	switch {
	case len(cands) == 1:
		st = "matched"
	case len(cands) > 1:
		st = "ambiguous"
	}
	return OrganizationResolution{Query: q, Status: st, Candidates: cands}, nil
}

func orgAsset(id, name string) Asset {
	return Asset{ID: id, Type: "Organization", Key: name, Content: map[string]any{"name": name}}
}

func TestResolveOrSuggest(t *testing.T) {
	g := fakeOrgSearch{orgs: []Asset{
		orgAsset("1", "SUNY Polytechnic Institute"),
		orgAsset("2", "Acme Corporation"),
		orgAsset("3", "Example Corp"),
		orgAsset("4", "Example Corp"),
	}}
	ctx := context.Background()

	// Exact name → a single match, no candidate list.
	if r, err := ResolveOrSuggest(ctx, g, "Acme Corporation", 5); err != nil ||
		r.Status != StatusMatched || r.Match == nil || r.Match.ID != "2" {
		t.Errorf("exact: %+v err=%v", r, err)
	}

	// Partial name → no exact match → closest stored name as a suggestion.
	r, err := ResolveOrSuggest(ctx, g, "SUNY Poly", 5)
	if err != nil || r.Status != StatusSuggestions || len(r.Candidates) == 0 || r.Candidates[0].ID != "1" {
		t.Errorf("partial: %+v err=%v", r, err)
	}

	// Several orgs with the same exact name → pick-one candidates.
	r, err = ResolveOrSuggest(ctx, g, "Example Corp", 5)
	if err != nil || r.Status != StatusSuggestions || len(r.Candidates) != 2 || r.Candidates[0].Why != "exact name" {
		t.Errorf("ambiguous: %+v err=%v", r, err)
	}

	// Nothing close → not found.
	if r, err := ResolveOrSuggest(ctx, g, "Umbrella Pharmaceuticals", 5); err != nil || r.Status != StatusNotFound {
		t.Errorf("not found: %+v err=%v", r, err)
	}
}

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
