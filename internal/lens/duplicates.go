// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// dupMaxBucket skips a shared key held by more organizations than this: a
// common name or address says nothing about any one pair.
const dupMaxBucket = GapMaxShared

// orgProfile is what the duplicate search knows about one organization.
type orgProfile struct {
	asset        graph.Asset
	names        []string
	brands       map[string]bool
	ids          map[string]map[string]bool
	jurisdiction string
	registration string
	contacts     map[string]bool
	locations    map[string]bool
	// addresses are the locations' normalized street addresses.
	addresses map[string]bool
	related   map[string]bool
	// parents are the organizations it is a unit or subsidiary of.
	parents map[string]bool
	// docs are what documents state relates this organization, by the
	// other organization's folded name (buildDocLinks).
	docs map[string]*docLink
	// evidence counts the facts recorded for the organization, to choose
	// which of two duplicates survives a merge.
	evidence int
	// idEdges and contactEdges are the edges that record each identifier
	// (by type and value) and each contact record, so a strong match can be
	// judged on whether only contributions recorded it.
	idEdges      map[string][]string
	contactEdges map[string][]string
}

// DuplicateCandidate is a pair of organizations the evidence says may be
// one company. Survivor is the organization a merge keeps.
type DuplicateCandidate struct {
	Survivor  graph.Asset `json:"survivor"`
	Duplicate graph.Asset `json:"duplicate"`
	Signals   []GapSignal `json:"signals"`
	Score     float64     `json:"score"`
	Decision  string      `json:"decision"`
	// Group is the number of organizations linked into one group with this
	// pair when there are more than two: each is proposed for merging into
	// the group's one survivor rather than into every other.
	Group int `json:"group,omitempty"`
}

// DuplicateReport is the result of a duplicate-organization search.
type DuplicateReport struct {
	Organizations int                  `json:"organizations"`
	Candidates    []DuplicateCandidate `json:"candidates"`
	Reads         int                  `json:"reads"`
	Truncated     bool                 `json:"truncated"`
	Reason        string               `json:"reason,omitempty"`
}

type dupSearch struct {
	ctx      context.Context
	graph    graph.Graph
	report   DuplicateReport
	profiles map[string]*orgProfile
	batch    batchAssets
	// links are what documents state relates organizations, read once per
	// search (documentLinks).
	links     docLinks
	linksRead bool
	// judge tells the strong signals that rest on contributions.
	judge *contributionJudge
	// resolved caches exact organization lookups by folded name.
	resolved map[string]string
	// crowded caches, by location ID, whether too many parties are tied to
	// a location for it to tell two organizations apart (crowdedLocation).
	crowded map[string]bool
}

// Crowded locations: an address tied to more organizations than the address
// hub limit (PivotSharedAddressOrgs without one), or to more than three times
// that in organizations and contact records together, is a registered
// agent's, an office tower's or an incubator's, and says nothing about one
// company.
const dupCrowdedHolderFactor = 3

// crowdedLocation reports whether too many parties are tied to a location for
// a shared address to link two organizations.
func (s *dupSearch) crowdedLocation(id string) (bool, error) {
	if c, ok := s.crowded[id]; ok {
		return c, nil
	}

	byLabel, err := s.labelEdges(id, "in", locationLabels)
	if err != nil {
		return false, err
	}

	// street_address ties a contact record; the other labels tie an
	// organization
	var orgs, holders int
	for _, label := range locationLabels {
		n := len(byLabel[label])
		holders += n
		if label != "street_address" {
			orgs += n
		}
	}

	limit := graph.HubLimit(s.ctx, s.graph, "street_address", "in", PivotSharedAddressOrgs)
	c := orgs > limit || holders > dupCrowdedHolderFactor*limit
	if s.crowded == nil {
		s.crowded = map[string]bool{}
	}
	s.crowded[id] = c
	return c, nil
}

// locationLabels are the relations tying an organization, or a contact
// record, to an address.
var locationLabels = []string{"legal_address", "hq_address", "street_address"}

// FindDuplicateOrganizations compares the stored organizations and returns
// the pairs the duplicate signals link, strongest first.
func FindDuplicateOrganizations(ctx context.Context, g graph.Graph) (DuplicateReport, error) {
	s := &dupSearch{ctx: ctx, graph: g, profiles: map[string]*orgProfile{}}

	orgs, err := s.duplicateCohort()
	if err != nil {
		return s.report, err
	}

	for _, o := range orgs {
		if graph.IsPlaceholder(o) || semantics.IsPlaceholderOrganization(graph.ContentString(o, "name")) {
			continue
		}

		p, err := s.profile(o)
		if err != nil {
			return s.report, err
		}

		s.profiles[o.ID] = p
	}

	pairs := s.pairs()
	renamed, err := s.renamePairs()
	if err != nil {
		return s.report, err
	}
	compared := map[[2]string]bool{}
	for _, pair := range pairs {
		compared[pair] = true
		compared[[2]string{pair[1], pair[0]}] = true
	}
	for _, pair := range renamed {
		if !compared[pair] {
			compared[pair] = true
			compared[[2]string{pair[1], pair[0]}] = true
			pairs = append(pairs, pair)
		}
	}
	s.report.Organizations = len(s.profiles)

	for _, pair := range pairs {
		if c, ok := s.candidate(s.profiles[pair[0]], s.profiles[pair[1]]); ok {
			s.report.Candidates = append(s.report.Candidates, c)
		}
	}

	s.finalize()
	return s.report, nil
}

// renamePairs returns the pairs of stored organizations a document says one
// was formerly known as, or merged with, the other, each name resolved
// exactly to one organization, profiling any not yet profiled. A renamed
// organization can share no name, identifier, contact or address with its
// former record, so the blocking keys never pair it.
func (s *dupSearch) renamePairs() ([][2]string, error) {
	links, err := s.documentLinks()
	if err != nil || len(links) == 0 {
		return nil, err
	}

	var out [][2]string
	seen := map[[2]string]bool{}
	for _, m := range links {
		for _, l := range m {
			if !l.former {
				continue
			}
			a, ok := s.resolveOrg(l.fromName)
			if !ok {
				continue
			}
			b, ok := s.resolveOrg(l.toName)
			if !ok || a == b {
				continue
			}
			key := [2]string{min(a, b), max(a, b)}
			if seen[key] {
				continue
			}
			seen[key] = true
			if !s.ensureProfile(a) || !s.ensureProfile(b) {
				continue
			}
			out = append(out, key)
		}
	}
	return out, nil
}

// ensureProfile profiles a stored organization when the search has not.
func (s *dupSearch) ensureProfile(id string) bool {
	if _, ok := s.profiles[id]; ok {
		return true
	}
	p, ok := s.profileID(id)
	if ok {
		s.profiles[id] = p
	}
	return ok
}

// resolveOrg finds the one stored organization a name names exactly, by name
// or legal name; an ambiguous or unknown name resolves to nothing.
func (s *dupSearch) resolveOrg(name string) (string, bool) {
	r, ok := s.graph.(graph.OrganizationResolver)
	if !ok || strings.TrimSpace(name) == "" {
		return "", false
	}
	key := docFold(name)
	if s.resolved == nil {
		s.resolved = map[string]string{}
	}
	if id, ok := s.resolved[key]; ok {
		return id, id != ""
	}

	id := ""
	for _, q := range []graph.OrganizationQuery{{Name: name}, {LegalName: name}} {
		res, err := r.ResolveOrganizations(s.ctx, q, 2)
		if err != nil || res.Status == "ambiguous" || res.Status == "truncated" {
			break
		}
		if res.Status == "matched" && len(res.Candidates) == 1 {
			id = res.Candidates[0].Asset.ID
			break
		}
	}
	s.resolved[key] = id
	return id, id != ""
}

// duplicateCohort is the set of organizations the sweep profiles. When the
// repository can group organizations by a shared blocking key in the database
// (CoKeyedGrouper), the cohort is the union of the organizations that share an
// identifier, contact record, registration or brand with another — the only
// organizations that can pair — loaded in one batch, so the sweep never reads
// the whole type. Otherwise it falls back to the bounded scan of every stored
// organization. The pairing and scoring that follow are identical either way.
func (s *dupSearch) duplicateCohort() ([]graph.Asset, error) {
	if cg, ok := s.graph.(CoKeyedGrouper); ok {
		orgs, err := s.coKeyedCohort(cg)
		if err == nil {
			return orgs, nil
		}
		if !errors.Is(err, ErrCoKeyedUnsupported) {
			return nil, err
		}
		// The repository lacks database-side grouping; fall back to the scan.
	}

	return s.graph.FindAssets(s.ctx, "Organization", time.Time{}, 0)
}

// coKeyedCohort gathers the organizations that share a blocking key with
// another, grouping them in the database, and loads them in one batch. A brand
// grouping relies on the brand_key tag the backfill materializes; abbreviation
// matches among the loaded organizations are still found by pairs().
func (s *dupSearch) coKeyedCohort(cg CoKeyedGrouper) ([]graph.Asset, error) {
	kinds := []CoKeyKind{CoKeyIdentifier, CoKeyContactRecord, CoKeyRegistration, CoKeyBrand}

	ids, err := coKeyedCohortIDs(s.ctx, cg, "Organization", kinds, dupMaxBucket)
	if err != nil {
		return nil, err
	}

	return s.loadCohort(ids)
}

// loadCohort batch-loads the cohort ids into assets, within the read budget.
func (s *dupSearch) loadCohort(ids []string) ([]graph.Asset, error) {
	sort.Strings(ids)
	if err := s.batch.loadIDs(s.ctx, s.graph, ids, s.spend); err != nil {
		return nil, err
	}

	orgs := make([]graph.Asset, 0, len(ids))
	for _, id := range ids {
		a, err := s.asset(id)
		if err != nil {
			continue
		}

		orgs = append(orgs, a)
	}

	return orgs, nil
}

// candidate scores one pair of organization profiles and returns the
// duplicate candidate it warrants, or ok=false when the pair shares no
// positive signal. The same scoring serves the whole-database sweep and the
// per-organization comparison.
func (s *dupSearch) candidate(a, b *orgProfile) (DuplicateCandidate, bool) {
	signals := pairSignals(a, b)
	if len(signals) == 0 {
		return DuplicateCandidate{}, false
	}
	if s.judge == nil {
		s.judge = newContributionJudge(s.ctx, s.graph)
	}
	s.judge.mark(signals, DuplicateSignal)

	score, decision := scoreSignals(signals, true, DuplicateSignal)
	if !hasPositive(signals) {
		return DuplicateCandidate{}, false
	}
	if decision == GapReview && hasStrength(signals, StrengthNegative) && !hasStrength(signals, StrengthStrong) {
		// Supporting evidence such as a shared name does not outweigh
		// evidence that the two are different companies.
		decision = GapWeak
	}
	if decision == GapWeak && (hasKind(signals, "name") || hasKind(signals, DocumentSignalKind)) &&
		!hasStrength(signals, StrengthNegative) {
		// A shared name, or a document stating a former name, with nothing
		// against it is for a person to decide: never merged automatically,
		// but not left unseen.
		decision = GapReview
	}

	survivor, dup := chooseSurvivor(a, b)
	return DuplicateCandidate{Survivor: survivor.asset, Duplicate: dup.asset,
		Signals: signals, Score: score, Decision: decision}, true
}

// finalize groups the collected candidates into one survivor per cluster and
// sorts them, strongest first.
func (s *dupSearch) finalize() {
	s.report.Candidates = s.groupCandidates(s.report.Candidates)
	sort.SliceStable(s.report.Candidates, func(i, j int) bool {
		ci, cj := s.report.Candidates[i], s.report.Candidates[j]
		if decisionRank(ci.Decision) != decisionRank(cj.Decision) {
			return decisionRank(ci.Decision) < decisionRank(cj.Decision)
		}
		if ci.Score != cj.Score {
			return ci.Score > cj.Score
		}

		return ci.Survivor.ID+ci.Duplicate.ID < cj.Survivor.ID+cj.Duplicate.ID
	})
}

// FormatDuplicateReport renders a duplicate search for a terminal, each
// pair with its decision and the signals behind it.
func FormatDuplicateReport(r DuplicateReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Compared %d organizations (%d reads).", r.Organizations, r.Reads)
	if r.Truncated {
		fmt.Fprintf(&b, " Incomplete: %s.", r.Reason)
	}

	b.WriteString("\n")
	if len(r.Candidates) == 0 {
		b.WriteString("No duplicate organizations found.\n")
		return b.String()
	}

	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "\n%s  %s [%s] and %s [%s], score %.2f\n", strings.ToUpper(c.Decision),
			graph.AssetLabel(c.Survivor), c.Survivor.ID, graph.AssetLabel(c.Duplicate), c.Duplicate.ID, c.Score)
		fmt.Fprintf(&b, "  keep %s [%s], merge %s [%s] into it\n", graph.AssetLabel(c.Survivor), c.Survivor.ID,
			graph.AssetLabel(c.Duplicate), c.Duplicate.ID)
		if c.Group > 2 {
			fmt.Fprintf(&b, "  one of %d organizations linked as the same, proposed for merging into one\n",
				c.Group)
		}
		for _, s := range c.Signals {
			def, _ := DuplicateSignal(s.Signal)
			mark := "+"
			if def.Strength == StrengthNegative {
				mark = "-"
			}

			fmt.Fprintf(&b, "  %s %s (%s): %s\n", mark, def.Title, def.Strength, s.Via)
		}
	}

	return b.String()
}

// partialRead names an edge read cut short: a store that cannot page
// returned only its first page.
func partialRead(id, dir, label string) string {
	if label == "" {
		label = "any"
	}

	return fmt.Sprintf("more %s %s edges on asset %s than one read returns", dir, label, id)
}
