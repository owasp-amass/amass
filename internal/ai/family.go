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
	"unicode"

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
	RenameWords     []string `json:"rename_words"`
	MinHostedNames  int      `json:"min_hosted_names"`
	DedicatedShare  float64  `json:"dedicated_share"`
}

// familyStrongTie is the weight of a registration, or of a name that is the
// domain's, when choosing the domain's main organization.
const familyStrongTie = 5

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
	// FamilyOther is an organization on the domain's assets that is not
	// family by name or registration, such as a hosting provider or a
	// vendor named on a certificate.
	FamilyOther = "other"
)

// FamilyMember is an organization tied to the domain, how it relates to
// the domain's main organization, and the evidence.
type FamilyMember struct {
	Organization Asset    `json:"organization"`
	Relation     string   `json:"relation"`
	Evidence     []string `json:"evidence"`
	// ByName reports that a same-institution member's name is a variant of
	// another's; only those are proposed for merging.
	ByName bool `json:"by_name,omitempty"`
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
	// MoreNames reports that the domain has more names than were sampled.
	MoreNames bool   `json:"more_names,omitempty"`
	Reads     int    `json:"reads"`
	Truncated bool   `json:"truncated"`
	Reason    string `json:"reason,omitempty"`
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
	// heldNames counts, for each organization holding a network, the
	// sampled names resolving into any network it holds.
	heldNames map[string]map[string]bool
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
		netNames: map[string]int{}, heldNames: map[string]map[string]bool{}}
	if err := s.profileAll(); err != nil {
		return s.finish(), err
	}
	if err := s.sampleDomain(root); err != nil && !errors.Is(err, errDupReadLimit) {
		return s.finish(), err
	}

	direct := s.directTies(domain)
	dedicated, sampled, err := s.classifyNetworks(domain, direct)
	if err != nil && !errors.Is(err, errDupReadLimit) {
		return s.finish(), err
	}

	s.members(domain, direct, dedicated)
	s.memberNetworks(domain, dedicated)
	s.relatedDomains(domain, dedicated, sampled)
	s.providerNetworks()
	return s.finish(), nil
}

// finish completes the report with what the search read.
func (s *familySearch) finish() FamilyReport {
	s.report.Reads = s.dup.report.Reads
	if s.dup.report.Truncated {
		s.truncate(s.dup.report.Reason)
	}

	return s.report
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

		children, err := s.dup.firstEdges(id, "out", "node", MaxEdgeRead)
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
	s.report.MoreNames = len(queue) > 0

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
		for _, h := range s.holders[b] {
			if s.heldNames[h] == nil {
				s.heldNames[h] = map[string]bool{}
			}
			s.heldNames[h][id] = true
		}
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

// directTies are the organizations tied to the domain by something other
// than a network: registering it, certificates for its names, or a
// registration contact role with an address in it.
func (s *familySearch) directTies(domain string) map[string][]string {
	ties := map[string][]string{}
	for id, p := range s.profiles {
		if p.registers[domain] {
			ties[id] = append(ties[id], "registered "+domain)
		}
		if n := p.certified[domain]; n > 0 {
			ties[id] = append(ties[id], fmt.Sprintf("named on %d certificate(s) for %s names", n, domain))
		}
		if p.contactFor[domain] && p.emails[domain] {
			ties[id] = append(ties[id], fmt.Sprintf("registration contact for %s with a %s address", domain, domain))
		}
	}

	// An organization named like the domain (Automattic for automattic.com,
	// NASA for nasa.gov) is tied when it is tied some other way, or when it
	// holds a network serving the domain's names: a company whose networks
	// serve several of its brands has no network mostly serving any one.
	label := domainLabel(domain)
	for id, p := range s.profiles {
		if !s.namedLike(p, label) {
			continue
		}
		if len(ties[id]) > 0 {
			ties[id] = append(ties[id], fmt.Sprintf("named like %s", domain))
			continue
		}
		// Its networks count together: a company's names spread over many
		// small networks (Automattic's /24s) have no one network serving
		// enough of them.
		if n := len(s.heldNames[id]); n >= s.rules.MinHostedNames {
			ties[id] = append(ties[id], fmt.Sprintf("named like %s, and %d of the sampled names resolve into its "+
				"networks", domain, n))
		}
	}

	return ties
}

// servingBlocks lists the networks serving enough of the domain's sampled
// names to be classified, most names first.
func (s *familySearch) servingBlocks() []string {
	blocks := make([]string, 0, len(s.netNames))
	for b, n := range s.netNames {
		if n >= s.rules.MinHostedNames {
			blocks = append(blocks, b)
		}
	}
	sort.Slice(blocks, func(i, j int) bool {
		if s.netNames[blocks[i]] != s.netNames[blocks[j]] {
			return s.netNames[blocks[i]] > s.netNames[blocks[j]]
		}
		return blocks[i] < blocks[j]
	})

	return blocks
}

// domainLabel is the label of a domain's registered name before its public
// suffix: nationalgridus for www.nationalgridus.com.
func domainLabel(domain string) string {
	label, _, _ := strings.Cut(registeredDomain(domain), ".")
	return label
}

// namedLike reports whether one of an organization's names is the domain
// label's (nameMatchesLabel).
func (s *familySearch) namedLike(p *familyProfile, label string) bool {
	stop := abbreviationStopWords()
	for b := range p.brands {
		if nameMatchesLabel(strings.Fields(b), label, s.rules.GenericWords, stop) {
			return true
		}
	}
	for _, n := range p.names {
		if nameMatchesLabel(addressWords(n), label, s.rules.GenericWords, stop) {
			return true
		}
	}

	return false
}

// nameMatchesLabel reports whether a domain label spells an organization's
// name: the leading words of the name written together are the label
// (automattic, uticauniversity) or begin it (national grid in
// nationalgridus), or the label is their initials (nasa for National
// Aeronautics and Space Administration, ngc for Northrop Grumman
// Corporation), or their initials followed by a last word in full (ngrid
// for National Grid). The leading words must include a word that is not
// generic, a label it begins must be at least five letters long, and
// initials at least three.
func nameMatchesLabel(words []string, label string, generic, stop []string) bool {
	if label == "" {
		return false
	}

	var compact, all, skipped strings.Builder
	distinctive := false
	for k, w := range words {
		w = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return r
			}
			return -1
		}, w)
		if w == "" {
			continue
		}
		if !slices.Contains(generic, w) {
			distinctive = true
			// The leading words' initials and this word in full: ngrid for
			// National Grid.
			if k > 0 && len(w) >= 4 && (all.String()+w == label || skipped.String()+w == label) {
				return true
			}
		}
		compact.WriteString(w)
		all.WriteByte(w[0])
		if !slices.Contains(stop, w) {
			skipped.WriteByte(w[0])
		}
		if !distinctive {
			continue
		}

		c := compact.String()
		if c == label || (len(c) >= 5 && strings.HasPrefix(label, c)) {
			return true
		}
		if k > 0 && len(label) >= 3 && (all.String() == label || skipped.String() == label) {
			return true
		}
	}

	return false
}

// classifyNetworks decides which networks serving enough of the domain's
// names are dedicated to it: those held by an organization directly tied
// to the domain, and those mostly serving its names among the names
// stored for them. It returns the dedicated netblocks and each sampled
// network's registered domains.
func (s *familySearch) classifyNetworks(domain string, direct map[string][]string) (map[string]bool,
	map[string]map[string]int, error) {
	dedicated := map[string]bool{}
	sampled := map[string]map[string]int{}
	kin, domains := s.kin(domain, direct)
	for _, b := range s.servingBlocks() {
		d, total, err := s.sampleNetwork(b)
		if err != nil {
			return dedicated, sampled, err
		}
		sampled[b] = d

		share, familyShare := 0.0, 0.0
		if total > 0 {
			share = float64(d[domain]) / float64(total)
			n := 0
			for dom := range domains {
				n += d[dom]
			}
			familyShare = float64(n) / float64(total)
		}
		held := false
		for _, h := range s.holders[b] {
			if len(direct[h]) > 0 || kin[h] {
				held = true
			}
		}

		net := FamilyNetwork{CIDR: s.cidrs[b], Names: s.netNames[b], Share: share,
			Dedicated: held || share >= s.rules.DedicatedShare || familyShare >= s.rules.DedicatedShare}
		if hs := s.holders[b]; len(hs) > 0 {
			if p, ok := s.profiles[hs[0]]; ok {
				net.Holder, net.HolderID = AssetLabel(p.asset), p.asset.ID
			}
		}
		s.report.Networks = append(s.report.Networks, net)
		if net.Dedicated {
			dedicated[b] = true
		}
	}

	return dedicated, sampled, nil
}

// kin returns the organizations whose networks are the domain's although
// they are not tied to it directly, and the registered domains whose names
// count with the domain's on a network. The seeds are the domain's
// registrants and the organizations named like it; kin are the
// organizations whose names are variants of a seed's (Northrop Grumman
// Systems Corporation for Northrop Grumman Corporation), and the domains are
// the ones the seeds and kin registered (ngc.com and northropgrumman.com
// for northgrum.com). A company's network serving several of its domains
// then counts as dedicated, though no one domain has most of its names.
func (s *familySearch) kin(domain string, direct map[string][]string) (map[string]bool, map[string]bool) {
	label := domainLabel(domain)
	seeds := map[string]bool{}
	for id := range direct {
		if p := s.profiles[id]; p.registers[domain] || s.namedLike(p, label) {
			seeds[id] = true
		}
	}

	kin := map[string]bool{}
	for id, p := range s.profiles {
		if seeds[id] {
			kin[id] = true
			continue
		}
		for seed := range seeds {
			if s.variantOf(p, s.profiles[seed]) {
				kin[id] = true
				break
			}
		}
	}

	domains := map[string]bool{domain: true}
	for id := range kin {
		for d := range s.profiles[id].registers {
			domains[registeredDomain(d)] = true
		}
	}

	return kin, domains
}

// variantOf reports whether one organization's name is the other's or a
// variant of it, in either direction.
func (s *familySearch) variantOf(a, b *familyProfile) bool {
	for na := range a.brands {
		for nb := range b.brands {
			if na == nb || nameVariant(na, nb, s.rules.GenericWords) || nameVariant(nb, na, s.rules.GenericWords) {
				return true
			}
		}
	}

	return false
}

// memberNetworks marks the networks held by the institution itself (a
// same-institution member or a department) as the family's, however few of
// the names stored for them are the domain's: Northrop Grumman's network
// serving northgrum.com and its other domains is not a provider's.
func (s *familySearch) memberNetworks(domain string, dedicated map[string]bool) {
	own := map[string]int{}
	for i, m := range s.report.Members {
		if m.Relation == FamilySame || m.Relation == FamilyDepartment {
			own[m.Organization.ID] = i
		}
	}

	for i, n := range s.report.Networks {
		if n.Dedicated {
			continue
		}
		for b, cidr := range s.cidrs {
			if cidr != n.CIDR || s.netNames[b] != n.Names {
				continue
			}
			for _, h := range s.holders[b] {
				m, ok := own[h]
				if !ok {
					continue
				}
				s.report.Networks[i].Dedicated = true
				dedicated[b] = true
				s.report.Members[m].Evidence = append(s.report.Members[m].Evidence, fmt.Sprintf(
					"holds %s, which serves %d of the sampled %s names", cidr, n.Names, domain))
				break
			}
		}
	}
}

// providerNetworks marks the networks whose holders turned out to be
// providers rather than family: they are not the family's networks, however
// many of their stored names are the domain's.
func (s *familySearch) providerNetworks() {
	other := map[string]bool{}
	for _, m := range s.report.Members {
		if m.Relation == FamilyOther {
			other[m.Organization.ID] = true
		}
	}
	for i, n := range s.report.Networks {
		if n.Dedicated && other[n.HolderID] {
			s.report.Networks[i].Dedicated = false
		}
	}
}

// relatedDomains lists the other registered domains on dedicated networks
// held by the family's members.
func (s *familySearch) relatedDomains(domain string, dedicated map[string]bool, sampled map[string]map[string]int) {
	family := map[string]bool{}
	for _, m := range s.report.Members {
		if m.Relation != FamilyOther {
			family[m.Organization.ID] = true
		}
	}

	related := map[string]*RelatedDomain{}
	for b := range dedicated {
		held := false
		for _, h := range s.holders[b] {
			if family[h] {
				held = true
			}
		}
		if !held {
			continue
		}

		for d, n := range sampled[b] {
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
}

// sampleNetwork counts the registered domains of the names whose addresses
// are in the netblock.
func (s *familySearch) sampleNetwork(block string) (map[string]int, int, error) {
	out := map[string]int{}
	total := 0

	ips, err := s.dup.firstEdges(block, "out", "contains", s.rules.SampleNetwork)
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
			if name := contentString(a, "name"); name != "" && !reverseLookupName(a) {
				out[registeredDomain(name)]++
				total++
			}
		}
	}

	return out, total, nil
}

// members classifies the organizations tied to the domain against the one
// with the most ties.
func (s *familySearch) members(domain string, direct map[string][]string, dedicated map[string]bool) {
	label := domainLabel(domain)
	ties := map[string][]string{}
	weight := map[string]int{}
	for id, why := range direct {
		ties[id] = append(ties[id], why...)
		p := s.profiles[id]
		weight[id] += p.certified[domain]
		if p.registers[domain] {
			weight[id] += familyStrongTie
		}
		if s.namedLike(p, label) {
			weight[id] += familyStrongTie
		}
		if p.contactFor[domain] {
			weight[id]++
		}
	}
	for b := range dedicated {
		for _, id := range s.holders[b] {
			ties[id] = append(ties[id], fmt.Sprintf("holds %s, which serves %d of the sampled %s names", s.cidrs[b],
				s.netNames[b], domain))
			weight[id] += s.netNames[b]
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
	words := s.familyWords(main, same)
	for id, why := range ties {
		p := s.profiles[id]
		member := FamilyMember{Organization: p.asset, Evidence: why}
		switch r, ok := same[id]; {
		case id == main:
			member.Relation, member.ByName = FamilySame, true
			member.Evidence = append(member.Evidence, "the domain's main organization")
		case s.isDepartment(p, domain, words):
			member.Relation = FamilyDepartment
		case ok:
			member.Relation, member.ByName = FamilySame, r.byName
			member.Evidence = append(member.Evidence, r.why)
		case p.registers[domain] || s.sharesWord(p, words):
			member.Relation = FamilyAffiliate
		default:
			// A provider or vendor on the domain's assets: a network or a
			// certificate, without the institution's name or registration.
			member.Relation = FamilyOther
		}
		s.report.Members = append(s.report.Members, member)
	}

	// A unit recorded under a shorter name (Jet Propulsion Laboratory for
	// NASA Jet Propulsion Laboratory) is the same department.
	for i, m := range s.report.Members {
		p := s.profiles[m.Organization.ID]
		if m.Relation != FamilyOther || !s.hasUnitWord(p) {
			continue
		}
		for _, d := range s.report.Members {
			if d.Relation == FamilyDepartment && s.variantOf(p, s.profiles[d.Organization.ID]) {
				s.report.Members[i].Relation = FamilyDepartment
				s.report.Members[i].Evidence = append(s.report.Members[i].Evidence,
					"another name of the department "+AssetLabel(d.Organization))
				break
			}
		}
	}

	sort.Slice(s.report.Members, func(i, j int) bool {
		a, b := s.report.Members[i], s.report.Members[j]
		if familyRank(a.Relation) != familyRank(b.Relation) {
			return familyRank(a.Relation) < familyRank(b.Relation)
		}
		if weight[a.Organization.ID] != weight[b.Organization.ID] {
			return weight[a.Organization.ID] > weight[b.Organization.ID]
		}
		return a.Organization.ID < b.Organization.ID
	})
}

func familyRank(r string) int {
	switch r {
	case FamilySame:
		return 0
	case FamilyDepartment:
		return 1
	case FamilyAffiliate:
		return 2
	default:
		return 3
	}
}

type sameReason struct {
	why    string
	byName bool
}

// sameInstitution groups the tied organizations whose names are variants
// of each other or whose street addresses match, and returns why each
// member of the main organization's group belongs to it.
func (s *familySearch) sameInstitution(main string, ties map[string][]string) map[string]sameReason {
	ids := make([]string, 0, len(ties))
	for id := range ties {
		if !s.hasUnitWord(s.profiles[id]) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	same := map[string]sameReason{main: {why: "main", byName: true}}
	for changed := true; changed; {
		changed = false
		for _, id := range ids {
			if _, ok := same[id]; ok {
				continue
			}
			for _, other := range ids {
				if _, ok := same[other]; !ok {
					continue
				}
				if r, ok := s.sameAs(s.profiles[id], s.profiles[other]); ok {
					same[id], changed = r, true
					break
				}
			}
		}
	}

	delete(same, main)
	return same
}

// sameAs says why two organizations are one institution: a name variant,
// or else a matching street address.
func (s *familySearch) sameAs(a, b *familyProfile) (sameReason, bool) {
	for na := range a.brands {
		for nb := range b.brands {
			if na == nb {
				return sameReason{why: fmt.Sprintf("same name as %s", AssetLabel(b.asset)), byName: true}, true
			}
			if nameVariant(na, nb, s.rules.GenericWords) || nameVariant(nb, na, s.rules.GenericWords) {
				return sameReason{why: fmt.Sprintf("%q is a variant of %q (%s)", na, nb, AssetLabel(b.asset)),
					byName: true}, true
			}
		}
	}
	for na := range a.brands {
		for nb := range b.brands {
			if s.renamed(na, nb) {
				return sameReason{why: fmt.Sprintf("%q and %q (%s) differ only in words such as university or "+
					"college, as after a rename; not proposed for merging", na, nb, AssetLabel(b.asset))}, true
			}
		}
	}
	if k := firstShared(a.addresses, b.addresses); k != "" {
		street, _, _ := strings.Cut(k, "|")
		return sameReason{why: "same street address as " + AssetLabel(b.asset) + " (" + street +
			"); the address alone is not proposed for merging"}, true
	}

	return sameReason{}, false
}

// renamed reports whether two names have the same distinctive words and
// differ only in rename_words (and joining words), as Utica College and
// Utica University do after the college became a university. Hopkins
// University and Hopkins Hospital differ in a word that is not a rename
// word, so they stay apart.
func (s *familySearch) renamed(a, b string) bool {
	wa, wb := strings.Fields(a), strings.Fields(b)
	stop := abbreviationStopWords()
	distinct := func(ws []string) map[string]bool {
		out := map[string]bool{}
		for _, w := range ws {
			if !slices.Contains(s.rules.GenericWords, w) {
				out[w] = true
			}
		}
		return out
	}

	da, db := distinct(wa), distinct(wb)
	if len(da) == 0 || len(da) != len(db) {
		return false
	}
	for w := range da {
		if !db[w] {
			return false
		}
	}

	rename := false
	for _, pair := range [][2][]string{{wa, wb}, {wb, wa}} {
		for _, w := range pair[0] {
			if slices.Contains(pair[1], w) {
				continue
			}
			switch {
			case slices.Contains(s.rules.RenameWords, w):
				rename = true
			case slices.Contains(stop, w):
			default:
				return false
			}
		}
	}

	return rename
}

// familyWords are the distinctive words of the main organization's and
// its same-institution members' names.
func (s *familySearch) familyWords(main string, same map[string]sameReason) map[string]bool {
	out := map[string]bool{}
	add := func(p *familyProfile) {
		for b := range p.brands {
			for _, w := range strings.Fields(b) {
				if len(w) >= 3 && !slices.Contains(s.rules.GenericWords, w) {
					out[w] = true
				}
			}
		}
	}

	add(s.profiles[main])
	for id, r := range same {
		if r.byName {
			add(s.profiles[id])
		}
	}

	return out
}

// sharesWord reports whether an organization's name has one of the
// family's distinctive words.
func (s *familySearch) sharesWord(p *familyProfile, words map[string]bool) bool {
	for b := range p.brands {
		for _, w := range strings.Fields(b) {
			if words[w] {
				return true
			}
		}
	}

	return false
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
func (s *familySearch) isDepartment(p *familyProfile, domain string, words map[string]bool) bool {
	// A unit word alone is not enough: a vendor on a certificate or a
	// provider holding a network may have one in its name. A department also
	// carries the institution's name or is one of the domain's own
	// registration contacts.
	if !s.sharesWord(p, words) && !p.registers[domain] && !p.contactFor[domain] {
		return false
	}

	return s.hasUnitWord(p)
}

// hasUnitWord reports whether an organization's name carries one of
// department_words. Such a name is never merged into the institution.
func (s *familySearch) hasUnitWord(p *familyProfile) bool {
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
	more := ""
	if r.MoreNames {
		more = "; it has more"
	}
	fmt.Fprintf(&b, "Organization family of %s (%d of its names sampled%s, %d reads).", r.Domain, r.SampledNames,
		more, r.Reads)
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
		FamilyAffiliate: "Affiliates", FamilyOther: "Other organizations on its assets (providers and vendors)"}
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
			kind := "provider"
			if n.Dedicated {
				kind = "the family's"
			}
			holder := n.Holder
			if holder == "" {
				holder = "holder unknown"
			}
			fmt.Fprintf(&b, "  %s (%s): %d of the sampled names, %s, %.0f%% of the names stored for it are the "+
				"domain's\n", n.CIDR, holder, n.Names, kind, n.Share*100)
		}
	}
	if len(r.RelatedDomains) > 0 {
		b.WriteString("\nOther registered domains on the family's networks:\n")
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
			if !m.ByName {
				// A shared address alone is reported, never merged.
				continue
			}
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
