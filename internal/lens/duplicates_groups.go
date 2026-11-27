// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"sort"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// CompareOrganization scores the organization orgID against a bounded set of
// candidate organizations — the others that share an identifier, phone or
// address with it — and returns the duplicate candidates they warrant, with
// the same signals and scoring as the whole-database sweep. The caller
// supplies the candidates, so the comparison is bounded and needs no full
// scan. Read-only.
func CompareOrganization(ctx context.Context, g graph.Graph, orgID string, candidateIDs []string) (DuplicateReport, error) {
	return CompareOrganizations(ctx, g, []string{orgID}, candidateIDs)
}

// CompareOrganizations scores a set of seed organizations against one another
// and against a bounded set of candidate organizations — the others that
// share a name, identifier, phone or address with a seed — and returns the
// duplicate candidates they warrant, with the same signals and scoring as the
// whole-database sweep. The caller supplies the seeds (typically the
// organizations an enumeration touched) and their gathered candidates, so the
// comparison is bounded and needs no full scan: it is the incremental
// counterpart to FindDuplicateOrganizations. Read-only.
func CompareOrganizations(ctx context.Context, g graph.Graph, seedIDs, candidateIDs []string) (DuplicateReport, error) {
	s := &dupSearch{ctx: ctx, graph: g, profiles: map[string]*orgProfile{}}

	seed := make(map[string]bool, len(seedIDs))
	var seeds []string
	for _, id := range seedIDs {
		if seed[id] {
			continue
		}
		seed[id] = true
		seeds = append(seeds, id)
	}

	// profile the seeds
	for _, id := range seeds {
		if s.report.Truncated {
			break
		}
		if p, ok := s.profileID(id); ok {
			s.profiles[id] = p
		}
	}

	// a touched organization a document says was renamed from, or merged
	// with, another is compared with that one too, though they share no
	// blocking key
	for _, id := range seeds {
		p, ok := s.profiles[id]
		if !ok {
			continue
		}
		for _, l := range p.docs {
			if !l.former {
				continue
			}
			if other, ok := s.resolveOrg(l.toName); ok && other != id {
				candidateIDs = append(candidateIDs, other)
			}
		}
	}

	// profile the non-seed candidates, keeping only those actually profiled
	candSeen := make(map[string]bool, len(candidateIDs))
	var cands []string
	for _, id := range candidateIDs {
		if seed[id] || candSeen[id] {
			continue
		}
		candSeen[id] = true
		if s.report.Truncated {
			continue
		}
		if p, ok := s.profileID(id); ok {
			s.profiles[id] = p
			cands = append(cands, id)
		}
	}

	s.report.Organizations = len(s.profiles)

	for i, sid := range seeds {
		sp, ok := s.profiles[sid]
		if !ok {
			continue
		}

		// each seed against the later seeds, so a pair of touched
		// organizations is scored once
		for _, oid := range seeds[i+1:] {
			op, ok := s.profiles[oid]
			if !ok {
				continue
			}
			if c, ok := s.candidate(sp, op); ok {
				s.report.Candidates = append(s.report.Candidates, c)
			}
		}

		// each seed against every non-seed candidate
		for _, cid := range cands {
			if c, ok := s.candidate(sp, s.profiles[cid]); ok {
				s.report.Candidates = append(s.report.Candidates, c)
			}
		}
	}

	s.finalize()
	return s.report, nil
}

// profileID profiles the stored organization id, skipping placeholders. It
// returns ok=false when the asset cannot be read or is a placeholder, and
// marks the report truncated when the read budget is reached.
func (s *dupSearch) profileID(id string) (*orgProfile, bool) {
	a, err := s.graph.GetAsset(s.ctx, id)
	if err != nil {
		return nil, false
	}
	if graph.IsPlaceholder(a) || semantics.IsPlaceholderOrganization(graph.ContentString(a, "name")) {
		return nil, false
	}

	p, err := s.profile(a)
	if err != nil {
		return nil, false
	}

	return p, true
}

// groupCandidates collapses organizations stored several times into one
// group each. Pairs that are proposed or sent to review link their
// organizations; in a group of more than two, the organization
// chooseSurvivor ranks first survives, and only the pairs with it are kept,
// so five records of one organization become four proposals instead of ten. A member
// with no pair of its own with the survivor keeps its strongest pair.
// Pairs too weak to propose are left as they are.
func (s *dupSearch) groupCandidates(cands []DuplicateCandidate) []DuplicateCandidate {
	parent := map[string]string{}
	var find func(string) string
	find = func(id string) string {
		if p, ok := parent[id]; ok && p != id {
			r := find(p)
			parent[id] = r
			return r
		}

		parent[id] = id
		return id
	}

	linked := func(c DuplicateCandidate) bool { return c.Decision != GapWeak }
	for _, c := range cands {
		if linked(c) {
			parent[find(c.Survivor.ID)] = find(c.Duplicate.ID)
		}
	}

	members := map[string][]string{}
	for id := range parent {
		r := find(id)
		members[r] = append(members[r], id)
	}

	survivor := map[string]string{}
	for r, ids := range members {
		if len(ids) < 3 {
			continue
		}

		sort.Strings(ids)
		best := s.profiles[ids[0]]
		for _, id := range ids[1:] {
			best, _ = chooseSurvivor(best, s.profiles[id])
		}

		survivor[r] = best.asset.ID
	}

	// Each non-survivor keeps its pair with the survivor, or else its
	// strongest pair.
	keep := map[int]bool{}
	chosen := map[string]int{}
	for i, c := range cands {
		if !linked(c) {
			keep[i] = true
			continue
		}

		r := find(c.Survivor.ID)
		top, grouped := survivor[r]
		if !grouped {
			keep[i] = true
			continue
		}

		dup := c.Duplicate.ID
		withTop := c.Survivor.ID == top
		prev, seen := chosen[dup]
		switch {
		case !seen:
			chosen[dup] = i
		case withTop && cands[prev].Survivor.ID != top:
			chosen[dup] = i
		case withTop == (cands[prev].Survivor.ID == top) && c.Score > cands[prev].Score:
			chosen[dup] = i
		}
	}
	for dup, i := range chosen {
		if dup != survivor[find(dup)] {
			keep[i] = true
		}
	}

	out := make([]DuplicateCandidate, 0, len(keep))
	for i, c := range cands {
		if !keep[i] {
			continue
		}
		if _, grouped := survivor[find(c.Survivor.ID)]; grouped && linked(c) {
			c.Group = len(members[find(c.Survivor.ID)])
		}

		out = append(out, c)
	}

	return out
}

func decisionRank(d string) int {
	switch d {
	case GapPropose:
		return 0
	case GapReview:
		return 1
	default:
		return 2
	}
}

func hasPositive(signals []GapSignal) bool {
	for _, s := range signals {
		if def, ok := DuplicateSignal(s.Signal); ok && def.Strength != StrengthNegative {
			return true
		}
	}

	return false
}

func hasKind(signals []GapSignal, kind string) bool {
	for _, s := range signals {
		if s.Kind == kind {
			return true
		}
	}

	return false
}

func hasStrength(signals []GapSignal, strength string) bool {
	for _, s := range signals {
		// a strong signal that rests on contributions is supporting
		if def, ok := DuplicateSignal(s.Signal); ok && def.Strength == strength &&
			(strength != StrengthStrong || !s.Contributed) {
			return true
		}
	}

	return false
}
