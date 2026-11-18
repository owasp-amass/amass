// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

const (
	// dupMaxOrganizations bounds the organizations one search compares.
	dupMaxOrganizations = 5000
	// dupMaxBucket skips a shared key held by more organizations than
	// this: a common name or address says nothing about any one pair.
	dupMaxBucket = GapMaxShared
	// dupMaxReads bounds the database reads of one search.
	dupMaxReads = 40000
	// dupMaxContacts bounds the contact records read per organization.
	dupMaxContacts = 50
)

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
	// evidence counts the facts recorded for the organization, to choose
	// which of two duplicates survives a merge.
	evidence int
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
}

var errDupReadLimit = errors.New("database read limit")

// FindDuplicateOrganizations compares the stored organizations and returns
// the pairs the duplicate signals link, strongest first.
func FindDuplicateOrganizations(ctx context.Context, g graph.Graph) (DuplicateReport, error) {
	s := &dupSearch{ctx: ctx, graph: g, profiles: map[string]*orgProfile{}}

	orgs, err := g.FindAssets(ctx, "Organization", time.Time{}, dupMaxOrganizations+1)
	if err != nil {
		return s.report, err
	}
	if len(orgs) > dupMaxOrganizations {
		orgs = orgs[:dupMaxOrganizations]
		s.truncate(fmt.Sprintf("more than %d organizations", dupMaxOrganizations))
	}

	for _, o := range orgs {
		if graph.IsPlaceholder(o) || semantics.IsPlaceholderOrganization(graph.ContentString(o, "name")) {
			continue
		}

		p, err := s.profile(o)
		if errors.Is(err, errDupReadLimit) {
			s.truncate(err.Error())
			break
		} else if err != nil {
			return s.report, err
		}

		s.profiles[o.ID] = p
	}

	s.report.Organizations = len(s.profiles)

	for _, pair := range s.pairs() {
		if c, ok := s.candidate(s.profiles[pair[0]], s.profiles[pair[1]]); ok {
			s.report.Candidates = append(s.report.Candidates, c)
		}
	}

	s.finalize()
	return s.report, nil
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

	score, decision := scoreSignals(signals, true, DuplicateSignal)
	if !hasPositive(signals) {
		return DuplicateCandidate{}, false
	}
	if decision == GapReview && hasStrength(signals, StrengthNegative) && !hasStrength(signals, StrengthStrong) {
		// Supporting evidence such as a shared name does not outweigh
		// evidence that the two are different companies.
		decision = GapWeak
	}
	if decision == GapWeak && hasKind(signals, "name") && !hasStrength(signals, StrengthNegative) {
		// A shared name with nothing against it is for a person to
		// decide: never merged automatically, but not left unseen.
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
	if errors.Is(err, errDupReadLimit) {
		s.truncate(err.Error())
		return nil, false
	} else if err != nil {
		return nil, false
	}

	return p, true
}

// groupCandidates collapses organizations stored several times into one
// group each. Pairs that are proposed or sent to review link their
// organizations; in a group of more than two, the organization
// chooseSurvivor ranks first survives, and only the pairs with it are kept,
// so five records of NASA become four proposals instead of ten. A member
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
		if def, ok := DuplicateSignal(s.Signal); ok && def.Strength == strength {
			return true
		}
	}

	return false
}

func (s *dupSearch) truncate(reason string) {
	if !s.report.Truncated {
		s.report.Truncated, s.report.Reason = true, reason
	}
}

// edges reads an asset's edges completely, a page at a time, within the
// search's read budget and lensMaxPerLabel edges. A read the budget or the
// cap cut short marks the report partial rather than silently dropping
// evidence.
func (s *dupSearch) edges(id, dir, label string) ([]graph.Relation, error) {
	if s.report.Reads >= dupMaxReads {
		return nil, errDupReadLimit
	}

	edges, more, err := graph.ReadEdges(s.ctx, s.graph, id, dir, label, LensMaxPerLabel, s.spend)
	if err == nil && more {
		s.truncate(partialRead(s.report.Reads >= dupMaxReads, id, dir, label))
	}

	return edges, err
}

// labelEdges reads an asset's edges for several labels in one direction
// as edges does for each, with every label's first edges in one read when
// the graph can.
func (s *dupSearch) labelEdges(id, dir string, labels []string) (map[string][]graph.Relation, error) {
	if s.report.Reads >= dupMaxReads {
		return nil, errDupReadLimit
	}

	byLabel, more, err := graph.ReadLabels(s.ctx, s.graph, id, dir, labels, LensMaxPerLabel, s.spend)
	if err != nil {
		return nil, err
	}
	for _, label := range labels {
		if more[label] {
			s.truncate(partialRead(s.report.Reads >= dupMaxReads, id, dir, label))
		}
	}

	return byLabel, nil
}

// firstEdges reads at most limit edges in one bounded read, for samples
// that are meant to be partial (a domain's names, a network's addresses).
func (s *dupSearch) firstEdges(id, dir, label string, limit int) ([]graph.Relation, error) {
	if !s.spend() {
		return nil, errDupReadLimit
	}
	if b, ok := s.graph.(graph.BoundedGraph); ok {
		edges, _, err := b.EdgesLimited(s.ctx, id, dir, label, time.Time{}, min(limit, graph.MaxEdgeRead))
		return edges, err
	}

	edges, err := s.graph.Edges(s.ctx, id, dir, label, time.Time{})
	if len(edges) > limit {
		edges = edges[:limit]
	}

	return edges, err
}

// spend counts one database read, or reports that the budget is spent.
func (s *dupSearch) spend() bool {
	if s.report.Reads >= dupMaxReads {
		return false
	}

	s.report.Reads++
	return true
}

func (s *dupSearch) asset(id string) (graph.Asset, error) {
	if a, ok := s.batch.get(id); ok {
		return a, nil
	}
	if s.report.Reads >= dupMaxReads {
		return graph.Asset{}, errDupReadLimit
	}

	s.report.Reads++
	return s.graph.GetAsset(s.ctx, id)
}

// profile reads an organization's names, identifiers, contact records,
// addresses and corporate links.
func (s *dupSearch) profile(o graph.Asset) (*orgProfile, error) {
	p := &orgProfile{asset: o, brands: map[string]bool{}, ids: map[string]map[string]bool{},
		contacts: map[string]bool{}, locations: map[string]bool{}, addresses: map[string]bool{},
		related: map[string]bool{}}
	p.addName(graph.ContentString(o, "name"))
	p.addName(graph.ContentString(o, "legal_name"))
	p.jurisdiction = strings.ToUpper(strings.TrimSpace(graph.ContentString(o, "jurisdiction")))
	p.registration = normRegistration(graph.ContentString(o, "registration_id"))

	ids, err := s.edges(o.ID, "out", "id")
	if err != nil {
		return nil, err
	}
	if err := s.batch.load(s.ctx, s.graph, ids, "out", s.spend); err != nil {
		return nil, err
	}
	for _, e := range ids {
		a, err := s.asset(e.ToID)
		if err != nil {
			return nil, err
		}

		p.addIdentifier(graph.ContentString(a, "id_type"), graph.ContentString(a, "id"))
	}

	addressLabels := []string{"legal_address", "hq_address", "location"}
	byLabel, err := s.labelEdges(o.ID, "out", addressLabels)
	if err != nil {
		return nil, err
	}
	for _, label := range addressLabels {
		locs := byLabel[label]
		for _, e := range locs {
			p.locations[e.ToID] = true
		}
	}

	crs, err := s.edges(o.ID, "in", "organization")
	if err != nil {
		return nil, err
	}
	for i, e := range crs {
		p.contacts[e.FromID] = true
		if i >= dupMaxContacts {
			continue
		}

		locs, err := s.edges(e.FromID, "out", "location")
		if err != nil {
			return nil, err
		}
		for _, l := range locs {
			p.locations[l.ToID] = true
		}
	}

	locIDs := make([]string, 0, len(p.locations))
	for id := range p.locations {
		locIDs = append(locIDs, id)
	}
	if err := s.batch.loadIDs(s.ctx, s.graph, locIDs, s.spend); err != nil {
		return nil, err
	}
	for id := range p.locations {
		loc, err := s.asset(id)
		if err != nil {
			return nil, err
		}
		if k := graph.LocationAddressKey(loc); k != "" {
			p.addresses[k] = true
		}
	}

	for _, dir := range []string{"out", "in"} {
		byLabel, err := s.labelEdges(o.ID, dir, parentChildLabels())
		if err != nil {
			return nil, err
		}
		for _, label := range parentChildLabels() {
			for _, e := range byLabel[label] {
				other := e.ToID
				if dir == "in" {
					other = e.FromID
				}

				p.related[other] = true
			}
		}
	}

	p.evidence = len(ids) + len(crs) + len(p.locations) + len(p.related)
	return p, nil
}

func (p *orgProfile) addName(name string) {
	name = strings.TrimSpace(name)
	if name == "" || slices.Contains(p.names, name) {
		return
	}

	p.names = append(p.names, name)
	if b := brandName(name); b != "" {
		p.brands[b] = true
	}
}

func (p *orgProfile) addIdentifier(idtype, value string) {
	idtype = strings.ToLower(strings.TrimSpace(idtype))
	value = strings.TrimSpace(value)
	if idtype == "" || value == "" {
		return
	}

	switch idtype {
	case "org_name", "legal_name":
		p.addName(value)
		return
	case "registration_id":
		value = normRegistration(value)
	default:
		value = strings.ToLower(value)
	}

	if p.ids[idtype] == nil {
		p.ids[idtype] = map[string]bool{}
	}

	p.ids[idtype][value] = true
}

func normRegistration(s string) string {
	return strings.ToUpper(strings.Join(strings.Fields(s), ""))
}

// brandName reduces an organization name to the form compared across
// sources: lowercase, without punctuation around words or a trailing
// legal form such as Inc, LLC or NV-SA.
func brandName(name string) string {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})
	for i, w := range words {
		words[i] = strings.Trim(w, ".,;:()\"'")
	}

	words = slices.DeleteFunc(words, func(w string) bool { return w == "" })

	forms := legalForms()
	for len(words) > 1 {
		if n := len(words); n > 2 && forms[normLegalForm(words[n-2]+" "+words[n-1])] {
			words = words[:n-2]
			continue
		}
		if forms[normLegalForm(words[len(words)-1])] {
			words = words[:len(words)-1]
			continue
		}

		break
	}

	return strings.Join(words, " ")
}

func parentChildLabels() []string {
	var out []string
	for _, s := range DuplicateSignals() {
		if s.Matcher == matchParentChild {
			out = append(out, s.Params.Labels...)
		}
	}

	return out
}

// pairs returns the organization pairs that share a name, an identifier,
// a registration, a contact record or an abbreviation. Pairs that share
// only an address are not compared.
func (s *dupSearch) pairs() [][2]string {
	buckets := map[string][]string{}
	add := func(key, id string) {
		if !slices.Contains(buckets[key], id) {
			buckets[key] = append(buckets[key], id)
		}
	}

	ids := make([]string, 0, len(s.profiles))
	for id := range s.profiles {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	for _, id := range ids {
		p := s.profiles[id]
		for b := range p.brands {
			add("brand:"+b, id)
			for _, sig := range signalsOf(matchAbbreviation) {
				if a := abbreviation(b, sig.Params.StopWords); len(a) >= sig.Params.MinLength {
					add("brand:"+a, id)
				}
			}
		}
		for t, vals := range p.ids {
			for v := range vals {
				add("id:"+t+":"+v, id)
			}
		}
		if p.jurisdiction != "" && p.registration != "" {
			add("reg:"+p.jurisdiction+":"+p.registration, id)
		}
		for cr := range p.contacts {
			add("cr:"+cr, id)
		}
	}

	seen := map[[2]string]bool{}
	var out [][2]string
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	for _, k := range keys {
		members := buckets[k]
		if len(members) < 2 || len(members) > dupMaxBucket {
			continue
		}
		for i := 0; i < len(members); i++ {
			for j := i + 1; j < len(members); j++ {
				pair := [2]string{members[i], members[j]}
				if pair[0] > pair[1] {
					pair[0], pair[1] = pair[1], pair[0]
				}
				if !seen[pair] {
					seen[pair] = true
					out = append(out, pair)
				}
			}
		}
	}

	return out
}

func signalsOf(matcher string) []OwnershipSignal {
	var out []OwnershipSignal
	for _, s := range DuplicateSignals() {
		if s.Matcher == matcher {
			out = append(out, s)
		}
	}

	return out
}

// abbreviation returns the initials of a name of two or more words,
// skipping stop words.
func abbreviation(name string, stop []string) string {
	var b strings.Builder
	words := 0
	for _, w := range strings.Fields(name) {
		if slices.Contains(stop, w) {
			continue
		}

		r := []rune(w)
		if len(r) == 0 || !unicode.IsLetter(r[0]) {
			continue
		}

		b.WriteRune(r[0])
		words++
	}
	if words < 2 {
		return ""
	}

	return b.String()
}

// pairSignals evaluates every duplicate signal for two organizations.
func pairSignals(a, b *orgProfile) []GapSignal {
	var out []GapSignal
	add := func(def OwnershipSignal, via string) {
		out = append(out, GapSignal{Signal: def.ID, Kind: def.Kind, Via: via})
	}

	sharedBrand := firstShared(a.brands, b.brands)
	for _, def := range DuplicateSignals() {
		switch def.Matcher {
		case matchSharedIdentifier:
			if def.Params.NamesMustAgree && sharedBrand == "" {
				continue
			}
			for _, t := range def.Params.IDTypes {
				if v := firstShared(a.ids[t], b.ids[t]); v != "" {
					add(def, t+" "+v)
					break
				}
			}
		case matchSharedRegistration:
			if a.jurisdiction != "" && a.jurisdiction == b.jurisdiction &&
				a.registration != "" && a.registration == b.registration {
				add(def, a.jurisdiction+" "+a.registration)
			}
		case matchSharedContactRecord:
			if cr := firstShared(a.contacts, b.contacts); cr != "" {
				add(def, "contact record "+cr)
			}
		case matchSameBrand:
			if sharedBrand != "" {
				add(def, sharedBrand)
			}
		case matchSharedLocation:
			if loc := firstShared(a.locations, b.locations); loc != "" {
				add(def, "location "+loc)
			} else if k := firstShared(a.addresses, b.addresses); k != "" {
				street, _, _ := strings.Cut(k, "|")
				add(def, "address "+street)
			}
		case matchAbbreviation:
			if via := abbreviates(a, b, def.Params.StopWords, def.Params.MinLength); via != "" {
				add(def, via)
			}
		case matchJurisdictionConflict:
			if via := jurisdictionConflict(a, b); via != "" {
				add(def, via)
			}
		case matchConflictingID:
			for _, t := range def.Params.IDTypes {
				if len(a.ids[t]) > 0 && len(b.ids[t]) > 0 && firstShared(a.ids[t], b.ids[t]) == "" {
					add(def, fmt.Sprintf("%s %s and %s", t, firstKey(a.ids[t]), firstKey(b.ids[t])))
					break
				}
			}
		case matchParentChild:
			if a.related[b.asset.ID] || b.related[a.asset.ID] {
				add(def, "linked in the corporate structure")
			}
		}
	}

	return out
}

// jurisdictionConflict describes how two organizations' registrations
// disagree: different countries, or one jurisdiction and two registration
// numbers.
func jurisdictionConflict(a, b *orgProfile) string {
	if a.jurisdiction == "" || b.jurisdiction == "" {
		return ""
	}

	ca, _, _ := strings.Cut(a.jurisdiction, "-")
	cb, _, _ := strings.Cut(b.jurisdiction, "-")
	switch {
	case ca != cb:
		return a.jurisdiction + " and " + b.jurisdiction
	case a.jurisdiction == b.jurisdiction && a.registration != "" && b.registration != "" &&
		a.registration != b.registration:
		return fmt.Sprintf("%s registrations %s and %s", a.jurisdiction, a.registration, b.registration)
	}

	return ""
}

func abbreviates(a, b *orgProfile, stop []string, minLen int) string {
	check := func(x, y *orgProfile) string {
		for long := range x.brands {
			abbr := abbreviation(long, stop)
			if len(abbr) < minLen {
				continue
			}
			for short := range y.brands {
				if short == abbr {
					return short + " = " + long
				}
			}
		}

		return ""
	}
	if v := check(a, b); v != "" {
		return v
	}

	return check(b, a)
}

func firstShared(a, b map[string]bool) string {
	var shared []string
	for k := range a {
		if b[k] {
			shared = append(shared, k)
		}
	}
	if len(shared) == 0 {
		return ""
	}

	sort.Strings(shared)
	return shared[0]
}

func firstKey(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}

	return keys[0]
}

// chooseSurvivor keeps the organization with more recorded evidence, then
// the one with a registry identity, then the older one.
func chooseSurvivor(a, b *orgProfile) (*orgProfile, *orgProfile) {
	rank := func(p *orgProfile) []int {
		registered := 0
		if p.jurisdiction != "" || len(p.ids["lei"]) > 0 {
			registered = 1
		}

		id, _ := strconv.Atoi(p.asset.ID)
		return []int{p.evidence, registered, -id}
	}

	if slices.Compare(rank(a), rank(b)) >= 0 {
		return a, b
	}

	return b, a
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

// partialRead names why an edge read was cut short.
func partialRead(budget bool, id, dir, label string) string {
	if budget {
		return "database read limit"
	}
	if label == "" {
		label = "any"
	}

	return fmt.Sprintf("more than %d %s %s edges on asset %s", LensMaxPerLabel, dir, label, id)
}
