// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/semantics"
)

//go:embed semantics/family.json
var familyJSON []byte

type familyRules struct {
	License         string   `json:"_license"`
	About           string   `json:"_about"`
	DepartmentWords []string `json:"department_words"`
	GenericWords    []string `json:"generic_words"`
	SampleNames     int      `json:"sample_names"`
	SampleNetwork   int      `json:"sample_network"`
	MinHostedNames  int      `json:"min_hosted_names"`
	DedicatedShare  float64  `json:"dedicated_share"`
}

var loadFamilyRules = sync.OnceValue(func() familyRules {
	var r familyRules
	if err := decodeStrict(familyJSON, &r); err != nil {
		panic("family.json: " + err.Error())
	}
	if r.SampleNames < 1 || r.SampleNetwork < 1 || r.SampleNames > MaxEdgeRead || r.SampleNetwork > MaxEdgeRead ||
		r.DedicatedShare <= 0 || r.DedicatedShare > 1 {
		panic("family.json: sample sizes must be in 1..500 and dedicated_share in (0, 1]")
	}

	return r
})

var relationTable = sync.OnceValues(semantics.Load)

// Family relations.
const (
	FamilySame       = "same_institution"
	FamilyDepartment = "department"
	FamilyAffiliate  = "affiliate"
)

// FamilyMember is an organization tied to the domain, how it relates to
// the domain's main organization, and the evidence.
type FamilyMember struct {
	Organization Asset    `json:"organization"`
	Relation     string   `json:"relation"`
	Evidence     []string `json:"evidence"`
}

// FamilyNetwork is a network that serves the domain's names.
type FamilyNetwork struct {
	CIDR      string `json:"cidr"`
	Holder    string `json:"holder,omitempty"`
	HolderID  string `json:"holder_id,omitempty"`
	Names     int    `json:"names"`
	Dedicated bool   `json:"dedicated"`
	// Share is the fraction of the names sampled from the network that are
	// the domain's.
	Share float64 `json:"share"`
}

// RelatedDomain is a registered domain served by the family's dedicated
// networks.
type RelatedDomain struct {
	Domain string `json:"domain"`
	Names  int    `json:"names"`
	CIDR   string `json:"cidr"`
}

// FamilyReport is the result of the organization family lens.
type FamilyReport struct {
	Domain         string          `json:"domain"`
	Main           *Asset          `json:"main,omitempty"`
	Members        []FamilyMember  `json:"members"`
	Networks       []FamilyNetwork `json:"networks"`
	RelatedDomains []RelatedDomain `json:"related_domains"`
	SampledNames   int             `json:"sampled_names"`
	Reads          int             `json:"reads"`
	Truncated      bool            `json:"truncated"`
	Reason         string          `json:"reason,omitempty"`
}

// familyProfile adds to an organization's profile what it controls.
type familyProfile struct {
	*orgProfile
	// registers are domains it is a controlling registration contact for;
	// contactFor those it is another registration contact for.
	registers  map[string]bool
	contactFor map[string]bool
	// certified counts the certificates naming it, by registered domain.
	certified map[string]int
	emails    map[string]bool
	netRecs   map[string]bool
	autnums   map[string]bool
}

type familySearch struct {
	dup      *dupSearch
	rules    familyRules
	table    *semantics.Table
	report   FamilyReport
	profiles map[string]*familyProfile
	// holders maps a netblock to the organizations holding it.
	holders  map[string][]string
	cidrs    map[string]string
	netNames map[string]int
}

// FindOrganizationFamily finds the organizations tied to an enumerated
// domain, classifies each as the same institution, a department or an
// affiliate of the domain's main organization, and lists the networks and
// registered domains that serve them. root is the domain's FQDN asset. It
// reads only.
func FindOrganizationFamily(ctx context.Context, graph Graph, root Asset) (FamilyReport, error) {
	table, err := relationTable()
	if err != nil {
		return FamilyReport{}, err
	}

	domain := strings.ToLower(strings.TrimSuffix(contentString(root, "name"), "."))
	if domain == "" {
		domain = strings.ToLower(root.Key)
	}

	s := &familySearch{dup: &dupSearch{ctx: ctx, graph: graph, profiles: map[string]*orgProfile{}},
		rules: loadFamilyRules(), table: table, report: FamilyReport{Domain: domain},
		profiles: map[string]*familyProfile{}, holders: map[string][]string{}, cidrs: map[string]string{},
		netNames: map[string]int{}}
	defer func() { s.report.Reads = s.dup.report.Reads }()

	if err := s.profileAll(); err != nil {
		return s.report, err
	}
	if err := s.sampleDomain(root); err != nil && !errors.Is(err, errDupReadLimit) {
		return s.report, err
	}

	dedicated, err := s.classifyNetworks(domain)
	if err != nil && !errors.Is(err, errDupReadLimit) {
		return s.report, err
	}

	s.members(domain, dedicated)
	if s.dup.report.Truncated {
		s.report.Truncated, s.report.Reason = true, s.dup.report.Reason
	}

	return s.report, nil
}

func (s *familySearch) truncate(reason string) {
	if !s.report.Truncated {
		s.report.Truncated, s.report.Reason = true, reason
	}
}

// profileAll profiles every organization and what it controls.
func (s *familySearch) profileAll() error {
	orgs, err := s.dup.graph.FindAssets(s.dup.ctx, "Organization", time.Time{}, dupMaxOrganizations+1)
	if err != nil {
		return err
	}
	if len(orgs) > dupMaxOrganizations {
		orgs = orgs[:dupMaxOrganizations]
		s.truncate(fmt.Sprintf("more than %d organizations", dupMaxOrganizations))
	}

	for _, o := range orgs {
		if isPlaceholder(o) || semantics.IsPlaceholderOrganization(contentString(o, "name")) {
			continue
		}

		p, err := s.dup.profile(o)
		if errors.Is(err, errDupReadLimit) {
			s.truncate(err.Error())
			return nil
		} else if err != nil {
			return err
		}

		fp := &familyProfile{orgProfile: p, registers: map[string]bool{}, contactFor: map[string]bool{},
			certified: map[string]int{}, emails: map[string]bool{}, netRecs: map[string]bool{}, autnums: map[string]bool{}}
		if err := s.controls(fp); errors.Is(err, errDupReadLimit) {
			s.truncate(err.Error())
			return nil
		} else if err != nil {
			return err
		}

		s.profiles[o.ID] = fp
	}

	return nil
}

// controls reads what points at the organization's contact records: the
// registrations, certificates and network records it is named on.
func (s *familySearch) controls(p *familyProfile) error {
	i := 0
	for cr := range p.contacts {
		if i >= dupMaxContacts {
			break
		}
		i++

		in, err := s.dup.edges(cr, "in", "")
		if err != nil {
			return err
		}
		for _, e := range in {
			if e.Label == "organization" {
				continue
			}

			src, err := s.dup.asset(e.FromID)
			if err != nil {
				return err
			}

			meaning, ok := s.table.Lookup(src.Type, e.Label, e.Type, "ContactRecord")
			controller := ok && meaning.Attribution == semantics.Controller
			switch src.Type {
			case "DomainRecord":
				if d := strings.ToLower(contentString(src, "domain")); d != "" {
					if controller {
						p.registers[d] = true
					} else {
						p.contactFor[d] = true
					}
				}
			case "TLSCertificate":
				if cn := contentString(src, "subject_common_name"); controller && cn != "" {
					p.certified[registeredDomain(strings.TrimPrefix(cn, "*."))]++
				}
			case "IPNetRecord":
				if controller {
					p.netRecs[src.ID] = true
				}
			case "AutnumRecord":
				if controller {
					p.autnums[src.ID] = true
				}
			}
		}

		ids, err := s.dup.edges(cr, "out", "id")
		if err != nil {
			return err
		}
		for _, e := range ids {
			a, err := s.dup.asset(e.ToID)
			if err != nil {
				return err
			}
			if strings.EqualFold(contentString(a, "id_type"), "email") {
				if _, dom, ok := strings.Cut(contentString(a, "id"), "@"); ok && dom != "" {
					p.emails[registeredDomain(dom)] = true
				}
			}
		}
	}

	return nil
}

// sampleDomain walks the domain's names and counts how many resolve into
// each network.
func (s *familySearch) sampleDomain(root Asset) error {
	queue := []string{root.ID}
	seen := map[string]bool{root.ID: true}
	for len(queue) > 0 && s.report.SampledNames < s.rules.SampleNames {
		id := queue[0]
		queue = queue[1:]
		s.report.SampledNames++

		if err := s.resolveName(id, s.netNames); err != nil {
			return err
		}

		children, err := s.dup.edges(id, "out", "node")
		if err != nil {
			return err
		}
		for _, c := range children {
			if !seen[c.ToID] {
				seen[c.ToID] = true
				queue = append(queue, c.ToID)
			}
		}
	}
	if len(queue) > 0 {
		s.truncate(fmt.Sprintf("sampled %d of the domain's names", s.report.SampledNames))
	}

	return nil
}

// resolveName adds one to counts for each netblock the name's addresses
// are in.
func (s *familySearch) resolveName(id string, counts map[string]int) error {
	recs, err := s.dup.edges(id, "out", "dns_record")
	if err != nil {
		return err
	}

	blocks := map[string]bool{}
	for _, r := range recs {
		if rr := relationRRType(r); rr != 1 && rr != 28 {
			continue
		}

		nets, err := s.dup.edges(r.ToID, "in", "contains")
		if err != nil {
			return err
		}
		for _, n := range nets {
			blocks[n.FromID] = true
		}
	}
	for b := range blocks {
		if err := s.holdersOf(b); err != nil {
			return err
		}
		counts[b]++
	}

	return nil
}

// holdersOf records who holds a netblock: the registrants of its network
// records, or of the AS numbers announcing it.
func (s *familySearch) holdersOf(block string) error {
	if _, ok := s.cidrs[block]; ok {
		return nil
	}

	a, err := s.dup.asset(block)
	if err != nil {
		return err
	}
	s.cidrs[block] = contentString(a, "cidr")

	regs, err := s.dup.edges(block, "out", "registration")
	if err != nil {
		return err
	}
	for _, r := range regs {
		for id, p := range s.profiles {
			if p.netRecs[r.ToID] && !slices.Contains(s.holders[block], id) {
				s.holders[block] = append(s.holders[block], id)
			}
		}
	}
	if len(s.holders[block]) > 0 {
		return nil
	}

	ases, err := s.dup.edges(block, "in", "announces")
	if err != nil {
		return err
	}
	for _, as := range ases {
		recs, err := s.dup.edges(as.FromID, "out", "registration")
		if err != nil {
			return err
		}
		for _, r := range recs {
			for id, p := range s.profiles {
				if p.autnums[r.ToID] && !slices.Contains(s.holders[block], id) {
					s.holders[block] = append(s.holders[block], id)
				}
			}
		}
	}

	return nil
}

// classifyNetworks samples each network serving enough of the domain's
// names: one mostly serving the domain is dedicated to it, the rest are
// hosting providers. It returns the dedicated netblocks.
func (s *familySearch) classifyNetworks(domain string) (map[string]bool, error) {
	dedicated := map[string]bool{}
	blocks := make([]string, 0, len(s.netNames))
	for b, n := range s.netNames {
		if n >= s.rules.MinHostedNames {
			blocks = append(blocks, b)
		}
	}
	sort.Slice(blocks, func(i, j int) bool { return s.netNames[blocks[i]] > s.netNames[blocks[j]] })

	related := map[string]*RelatedDomain{}
	for _, b := range blocks {
		domains, total, err := s.sampleNetwork(b)
		if err != nil {
			return dedicated, err
		}

		share := 0.0
		if total > 0 {
			share = float64(domains[domain]) / float64(total)
		}
		net := FamilyNetwork{CIDR: s.cidrs[b], Names: s.netNames[b], Share: share,
			Dedicated: share >= s.rules.DedicatedShare}
		if hs := s.holders[b]; len(hs) > 0 {
			if p, ok := s.profiles[hs[0]]; ok {
				net.Holder, net.HolderID = AssetLabel(p.asset), p.asset.ID
			}
		}
		s.report.Networks = append(s.report.Networks, net)
		if !net.Dedicated {
			continue
		}

		dedicated[b] = true
		for d, n := range domains {
			if d == domain {
				continue
			}
			if r, ok := related[d]; !ok || n > r.Names {
				related[d] = &RelatedDomain{Domain: d, Names: n, CIDR: s.cidrs[b]}
			}
		}
	}

	for _, r := range related {
		s.report.RelatedDomains = append(s.report.RelatedDomains, *r)
	}
	sort.Slice(s.report.RelatedDomains, func(i, j int) bool {
		a, b := s.report.RelatedDomains[i], s.report.RelatedDomains[j]
		if a.Names != b.Names {
			return a.Names > b.Names
		}
		return a.Domain < b.Domain
	})

	return dedicated, nil
}

// sampleNetwork counts the registered domains of the names whose addresses
// are in the netblock.
func (s *familySearch) sampleNetwork(block string) (map[string]int, int, error) {
	out := map[string]int{}
	total := 0

	var ips []Relation
	var err error
	if b, ok := s.dup.graph.(BoundedGraph); ok {
		if s.dup.report.Reads >= dupMaxReads {
			return out, 0, errDupReadLimit
		}
		s.dup.report.Reads++
		ips, _, err = b.EdgesLimited(s.dup.ctx, block, "out", "contains", time.Time{}, s.rules.SampleNetwork)
	} else {
		ips, err = s.dup.edges(block, "out", "contains")
	}
	if err != nil {
		return out, 0, err
	}

	for i, ip := range ips {
		if i >= s.rules.SampleNetwork {
			break
		}

		names, err := s.dup.edges(ip.ToID, "in", "dns_record")
		if err != nil {
			return out, total, err
		}
		for _, n := range names {
			a, err := s.dup.asset(n.FromID)
			if err != nil {
				return out, total, err
			}
			if name := contentString(a, "name"); name != "" {
				out[registeredDomain(name)]++
				total++
			}
		}
	}

	return out, total, nil
}

// members finds the organizations tied to the domain and classifies them
// against the one with the most ties.
func (s *familySearch) members(domain string, dedicated map[string]bool) {
	ties := map[string][]string{}
	weight := map[string]int{}
	tie := func(id, why string, w int) {
		if !slices.Contains(ties[id], why) {
			ties[id] = append(ties[id], why)
		}
		weight[id] += w
	}

	ids := make([]string, 0, len(s.profiles))
	for id := range s.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		p := s.profiles[id]
		if p.registers[domain] {
			tie(id, "registered "+domain, 10)
		}
		if n := p.certified[domain]; n > 0 {
			tie(id, fmt.Sprintf("named on %d certificate(s) for %s names", n, domain), n)
		}
		if p.contactFor[domain] && p.emails[domain] {
			tie(id, fmt.Sprintf("registration contact for %s with a %s address", domain, domain), 1)
		}
	}
	for b := range dedicated {
		for _, id := range s.holders[b] {
			tie(id, fmt.Sprintf("holds %s, which mostly serves %s names", s.cidrs[b], domain), s.netNames[b])
		}
	}
	if len(ties) == 0 {
		return
	}

	main := ""
	for id := range ties {
		if main == "" || weight[id] > weight[main] || (weight[id] == weight[main] && id < main) {
			main = id
		}
	}
	m := s.profiles[main].asset
	s.report.Main = &m

	same := s.sameInstitution(main, ties)
	for id, why := range ties {
		p := s.profiles[id]
		member := FamilyMember{Organization: p.asset, Evidence: why}
		switch {
		case id == main:
			member.Relation = FamilySame
			member.Evidence = append(member.Evidence, "the domain's main organization")
		case s.isDepartment(p):
			member.Relation = FamilyDepartment
		case same[id] != "":
			member.Relation = FamilySame
			member.Evidence = append(member.Evidence, same[id])
		default:
			member.Relation = FamilyAffiliate
		}
		s.report.Members = append(s.report.Members, member)
	}

	sort.Slice(s.report.Members, func(i, j int) bool {
		a, b := s.report.Members[i], s.report.Members[j]
		if familyRank(a.Relation) != familyRank(b.Relation) {
			return familyRank(a.Relation) < familyRank(b.Relation)
		}
		return weight[a.Organization.ID] > weight[b.Organization.ID]
	})
}

func familyRank(r string) int {
	switch r {
	case FamilySame:
		return 0
	case FamilyDepartment:
		return 1
	default:
		return 2
	}
}

// sameInstitution groups the tied organizations whose names are variants
// of each other or whose street addresses match, and returns why each
// member of the main organization's group belongs to it.
func (s *familySearch) sameInstitution(main string, ties map[string][]string) map[string]string {
	ids := make([]string, 0, len(ties))
	for id := range ties {
		if !s.isDepartment(s.profiles[id]) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	why := map[string]string{main: "main"}
	for changed := true; changed; {
		changed = false
		for _, id := range ids {
			if why[id] != "" {
				continue
			}
			for _, other := range ids {
				if why[other] == "" {
					continue
				}
				if r := s.sameAs(s.profiles[id], s.profiles[other]); r != "" {
					why[id], changed = r, true
					break
				}
			}
		}
	}

	delete(why, main)
	return why
}

// sameAs says why two organizations are one institution, or "".
func (s *familySearch) sameAs(a, b *familyProfile) string {
	if k := firstShared(a.addresses, b.addresses); k != "" {
		street, _, _ := strings.Cut(k, "|")
		return "same street address as " + AssetLabel(b.asset) + " (" + street + ")"
	}
	for na := range a.brands {
		for nb := range b.brands {
			if nameVariant(na, nb, s.rules.GenericWords) || nameVariant(nb, na, s.rules.GenericWords) {
				return fmt.Sprintf("%q is a variant of %q (%s)", na, nb, AssetLabel(b.asset))
			}
		}
	}

	return ""
}

// nameVariant reports whether name a is a variant of name b: its words are
// all in b, once a phrase of b may be written as its initials (SUNY for
// State University of New York), and it has a word that is not generic.
func nameVariant(a, b string, generic []string) bool {
	wa, wb := strings.Fields(a), strings.Fields(b)
	if len(wa) == 0 {
		return false
	}

	distinctive := false
	for _, w := range wa {
		if !slices.Contains(generic, w) {
			distinctive = true
			break
		}
	}
	if !distinctive {
		return false
	}

	have := map[string]bool{}
	for _, w := range wb {
		have[w] = true
	}
	// Initials skip short joining words: SUNY is State University of New
	// York.
	stop := abbreviationStopWords()
	for i := range wb {
		for j := i + 2; j <= len(wb); j++ {
			var all, skipped strings.Builder
			for _, w := range wb[i:j] {
				all.WriteByte(w[0])
				if !slices.Contains(stop, w) {
					skipped.WriteByte(w[0])
				}
			}
			have[all.String()] = true
			have[skipped.String()] = true
		}
	}
	for _, w := range wa {
		if !have[w] {
			return false
		}
	}

	return true
}

// abbreviationStopWords are the words initials skip, from the duplicate
// catalog's abbreviation signal.
func abbreviationStopWords() []string {
	var out []string
	for _, s := range signalsOf(matchAbbreviation) {
		out = append(out, s.Params.StopWords...)
	}

	return out
}

// isDepartment reports whether an organization's name carries a department
// or role word.
func (s *familySearch) isDepartment(p *familyProfile) bool {
	for _, name := range p.names {
		words := " " + strings.Join(addressWords(name), " ") + " "
		for _, d := range s.rules.DepartmentWords {
			if strings.Contains(words, " "+d+" ") {
				return true
			}
		}
	}

	return false
}

// FormatFamilyReport renders a family report for a terminal.
func FormatFamilyReport(r FamilyReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Organization family of %s (%d names sampled, %d reads).", r.Domain, r.SampledNames, r.Reads)
	if r.Truncated {
		fmt.Fprintf(&b, " Incomplete: %s.", r.Reason)
	}
	b.WriteString("\n")
	if r.Main == nil {
		b.WriteString("No stored organization is tied to the domain.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "Main organization: %s [%s]\n", AssetLabel(*r.Main), r.Main.ID)
	titles := map[string]string{FamilySame: "Same institution", FamilyDepartment: "Departments",
		FamilyAffiliate: "Affiliates"}
	last := ""
	for _, m := range r.Members {
		if m.Relation != last {
			fmt.Fprintf(&b, "\n%s:\n", titles[m.Relation])
			last = m.Relation
		}
		fmt.Fprintf(&b, "  %s [%s]\n", AssetLabel(m.Organization), m.Organization.ID)
		for _, e := range m.Evidence {
			fmt.Fprintf(&b, "    - %s\n", e)
		}
	}

	if len(r.Networks) > 0 {
		b.WriteString("\nNetworks serving its names:\n")
		for _, n := range r.Networks {
			kind := "hosting provider"
			if n.Dedicated {
				kind = "dedicated"
			}
			holder := n.Holder
			if holder == "" {
				holder = "holder unknown"
			}
			fmt.Fprintf(&b, "  %s (%s): %d of the sampled names, %s, %.0f%% of its names are the domain's\n",
				n.CIDR, holder, n.Names, kind, n.Share*100)
		}
	}
	if len(r.RelatedDomains) > 0 {
		b.WriteString("\nOther registered domains on its dedicated networks:\n")
		for _, d := range r.RelatedDomains {
			fmt.Fprintf(&b, "  %s (%d names, %s)\n", d.Domain, d.Names, d.CIDR)
		}
	}

	return b.String()
}

// FamilyProposals turns a family report into proposals for review: an
// org_unit relationship from the main organization to each department,
// and a merge of each organization that is the same institution as the
// main one. Affiliates are only reported; nothing records them.
func FamilyProposals(r FamilyReport) ([]OwnershipProposal, []DuplicateProposal) {
	if r.Main == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	main := *r.Main
	var units []OwnershipProposal
	var merges []DuplicateProposal
	for _, m := range r.Members {
		if m.Organization.ID == main.ID {
			continue
		}

		evidence := append([]string{"family of " + r.Domain}, m.Evidence...)
		switch m.Relation {
		case FamilyDepartment:
			edge := ProposedEdge{FromID: main.ID, FromType: "Organization", From: AssetLabel(main), Label: "org_unit",
				RelationType: "SimpleRelation", ToID: m.Organization.ID, ToType: "Organization",
				To: AssetLabel(m.Organization)}
			units = append(units, OwnershipProposal{ID: ProposalID(edge), Kind: ProposalKindOrgUnit,
				Owner: AssetLabel(main), OwnerID: main.ID, Asset: AssetLabel(m.Organization),
				AssetID: m.Organization.ID, AssetType: "Organization", Edge: edge, Decision: GapReview,
				Signals: evidence, Evidence: evidence, CreatedAt: now})
		case FamilySame:
			survivor, dup := main, m.Organization
			merges = append(merges, DuplicateProposal{ID: DuplicateProposalID(survivor, dup),
				Survivor: AssetLabel(survivor), SurvivorID: survivor.ID, Duplicate: AssetLabel(dup), DuplicateID: dup.ID,
				Decision: GapReview, Signals: evidence, CreatedAt: now})
		}
	}

	return units, merges
}

// SubmitFamily records a family's department and merge proposals not
// already in the journal and returns how many of each it added.
func (j *Journal) SubmitFamily(r FamilyReport) (int, int, error) {
	units, merges := FamilyProposals(r)
	addedUnits, err := j.SubmitOwnership(units)
	if err != nil {
		return 0, 0, fmt.Errorf("record department proposals: %w", err)
	}

	addedMerges, err := j.SubmitDuplicates(merges)
	if err != nil {
		return len(addedUnits), 0, fmt.Errorf("record merge proposals: %w", err)
	}

	return len(addedUnits), len(addedMerges), nil
}
