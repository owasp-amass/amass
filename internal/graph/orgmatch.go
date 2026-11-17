// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// Organization-name disambiguation, shared by every tool and lens that takes an
// organization by name (enumeration, the lenses, investigate, visualize).
//
// Resolving an organization needs an EXACT match: the resolver never guesses by
// similarity, so a misspelled or partial name resolves to nothing. This turns
// such a name into a short list of candidates for a person to choose from. It
// only proposes — the caller still selects exactly one, so a wrong guess never
// drives an action.

// Organization resolution statuses returned by ResolveOrSuggest.
const (
	StatusMatched     = "matched"     // exactly one organization matched
	StatusSuggestions = "suggestions" // no single match; candidates to choose from
	StatusNotFound    = "not_found"   // nothing close enough to offer
)

const (
	// orgSuggestPoolLimit bounds how many stored organizations the fuzzy
	// suggestion pass ranks.
	orgSuggestPoolLimit = 5000
	// orgExactCandidates bounds the exact resolver's candidate list.
	orgExactCandidates = 10
)

// OrgSearchGraph is a graph that can both resolve an exact organization and
// list organizations for fuzzy suggestion.
type OrgSearchGraph interface {
	FindAssets(context.Context, string, time.Time, int) ([]Asset, error)
	ResolveOrganizations(context.Context, OrganizationQuery, int) (OrganizationResolution, error)
}

// OrgResolution is the outcome of resolving an organization name: an exact
// match, a short list of candidates to choose from, or nothing.
type OrgResolution struct {
	Status     string     `json:"status"`
	Match      *Asset     `json:"match,omitempty"`
	Candidates []OrgMatch `json:"candidates,omitempty"`
}

// ResolveOrSuggest resolves an organization by name. One exact match is
// returned as Match; several same-name matches, or (failing that) the closest
// stored names, are returned as Candidates for a person to choose from. It
// never selects a candidate itself, so an inexact name never drives an action.
func ResolveOrSuggest(ctx context.Context, g OrgSearchGraph, name string, limit int) (OrgResolution, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return OrgResolution{}, errors.New("organization name is required")
	}
	if limit <= 0 {
		limit = 5
	}

	res, err := g.ResolveOrganizations(ctx, OrganizationQuery{Name: name}, orgExactCandidates)
	if err != nil {
		return OrgResolution{}, err
	}
	switch res.Status {
	case "matched":
		m := res.Candidates[0].Asset
		return OrgResolution{Status: StatusMatched, Match: &m}, nil
	case "ambiguous", "truncated":
		// Several organizations carry this exact name; let the user pick.
		out := make([]OrgMatch, 0, limit)
		for _, c := range res.Candidates {
			out = append(out, OrgMatch{OrgCandidate: candidateFromAsset(c.Asset), Score: 1, Why: "exact name"})
			if len(out) >= limit {
				break
			}
		}
		return OrgResolution{Status: StatusSuggestions, Candidates: out}, nil
	}

	// Nothing matched exactly: offer the closest stored names.
	assets, err := g.FindAssets(ctx, "Organization", time.Time{}, orgSuggestPoolLimit)
	if err != nil {
		return OrgResolution{}, err
	}
	pool := make([]OrgCandidate, 0, len(assets))
	for _, a := range assets {
		pool = append(pool, candidateFromAsset(a))
	}
	matches := RankOrganizations(name, pool, limit)
	if len(matches) == 0 {
		return OrgResolution{Status: StatusNotFound}, nil
	}
	return OrgResolution{Status: StatusSuggestions, Candidates: matches}, nil
}

// candidateFromAsset reads an Organization asset into an OrgCandidate. Domains
// is left zero; a caller that needs it fills it from the controlled footprint.
func candidateFromAsset(a Asset) OrgCandidate {
	return OrgCandidate{
		ID:           a.ID,
		Name:         ContentString(a, "name"),
		LegalName:    ContentString(a, "legal_name"),
		Jurisdiction: ContentString(a, "jurisdiction"),
	}
}

// orgMatchFloor is the lowest score a candidate needs to be offered.
const orgMatchFloor = 0.6

// OrgCandidate is one stored organization the search may offer.
type OrgCandidate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	LegalName    string `json:"legal_name,omitempty"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
	// Domains is how many domains the organization controls; it both ranks
	// ties and tells the caller whether the org can actually seed a run.
	Domains int `json:"domains"`
}

// OrgMatch is a candidate with why and how well it matched the query.
type OrgMatch struct {
	OrgCandidate
	Score float64 `json:"score"`
	Why   string  `json:"why"`
}

// RankOrganizations ranks stored organizations against a typed name and returns
// the best matches for a person to choose from, most likely first. It is for
// human disambiguation only; callers must never auto-select a result.
func RankOrganizations(query string, cands []OrgCandidate, limit int) []OrgMatch {
	q := normOrg(query)
	if q == "" {
		return nil
	}
	qt := orgTokens(q)

	var out []OrgMatch
	for _, c := range cands {
		score, why := scoreOrgPair(q, qt, normOrg(c.Name))
		if ln := normOrg(c.LegalName); ln != "" && ln != normOrg(c.Name) {
			if s, w := scoreOrgPair(q, qt, ln); s > score {
				score, why = s, w
			}
		}
		if score >= orgMatchFloor {
			out = append(out, OrgMatch{OrgCandidate: c, Score: score, Why: why})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Domains != out[j].Domains {
			return out[i].Domains > out[j].Domains // a seedable org first
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// scoreOrgPair scores a normalized query against a normalized candidate name,
// returning the score and a short reason.
func scoreOrgPair(q string, qt []string, name string) (float64, string) {
	if name == "" {
		return 0, ""
	}
	if q == name {
		return 1, "exact name"
	}

	// Every query token present in the candidate (equal, a prefix, or a near
	// spelling) covers the "left out part" and "misspelled a word" cases, such
	// as "suny poly" or "suny polytecnic" for "SUNY Polytechnic Institute".
	if len(q) >= 3 && len(qt) > 0 {
		nt := orgTokens(name)
		matched := 0
		for _, t := range qt {
			for _, u := range nt {
				if tokenMatches(t, u) {
					matched++
					break
				}
			}
		}
		if matched == len(qt) {
			return 0.9, "matches your terms"
		}
	}

	// Whole-string edit distance catches a misspelling that spans tokens.
	d := editDistance(q, name)
	m := len(q)
	if len(name) > m {
		m = len(name)
	}
	if m == 0 {
		return 0, ""
	}
	if sim := 1 - float64(d)/float64(m); sim >= orgMatchFloor {
		return sim, "similar spelling"
	}
	return 0, ""
}

// tokenMatches reports whether a query token matches a candidate token: equal,
// one a prefix of the other, or within a small edit distance for its length.
func tokenMatches(t, u string) bool {
	if t == u {
		return true
	}
	if len(t) >= 3 && strings.HasPrefix(u, t) {
		return true
	}
	if len(u) >= 3 && strings.HasPrefix(t, u) {
		return true
	}
	tol := 0
	switch n := len(t); {
	case n >= 7:
		tol = 2
	case n >= 4:
		tol = 1
	}
	return tol > 0 && editDistance(t, u) <= tol
}

// orgLegalForms are trailing company-form tokens dropped before comparison, so
// a name matches whether or not its legal suffix is given.
var orgLegalForms = map[string]bool{
	"inc": true, "incorporated": true, "corp": true, "corporation": true,
	"co": true, "company": true, "llc": true, "llp": true, "lp": true,
	"ltd": true, "limited": true, "plc": true, "pllc": true, "gmbh": true,
	"ag": true, "sa": true, "nv": true, "bv": true, "sarl": true, "srl": true,
	"spa": true, "pty": true, "pte": true, "oy": true, "ab": true, "as": true,
	"kk": true, "sas": true, "pbc": true, "de": true, "cv": true, "rl": true,
}

// normOrg lowercases a name, reduces runs of non-alphanumeric characters to a
// single space, and drops trailing legal-form tokens.
func normOrg(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			space = false
		case !space:
			b.WriteByte(' ')
			space = true
		}
	}
	words := strings.Fields(b.String())
	for len(words) > 1 && orgLegalForms[words[len(words)-1]] {
		words = words[:len(words)-1]
	}
	return strings.Join(words, " ")
}

func orgTokens(norm string) []string { return strings.Fields(norm) }

// editDistance is the Levenshtein distance between two short strings.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
