// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// countNameNetblocks adds one to counts for each netblock the name's
// addresses are in, and records the name under each block's holders. (Not to
// be confused with the package-level resolveName, which follows a name's DNS
// alias chain.)
func (s *familySearch) countNameNetblocks(id string, counts map[string]int) error {
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

// addHolders records the organizations a network or AS registration
// record names as controlling it as holders of the block.
func (s *familySearch) addHolders(block, recID string) error {
	orgs, err := s.recordOrganizations(recID, true)
	if err != nil {
		return err
	}
	for _, id := range orgs {
		if err := s.profileOrganization(id); err != nil {
			return err
		}
		if _, ok := s.profiles[id]; ok && !slices.Contains(s.holders[block], id) {
			s.holders[block] = append(s.holders[block], id)
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

	s.cidrs[block] = graph.ContentString(a, "cidr")

	regs, err := s.dup.edges(block, "out", "registration")
	if err != nil {
		return err
	}
	for _, r := range regs {
		if err := s.addHolders(block, r.ToID); err != nil {
			return err
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
			if err := s.addHolders(block, r.ToID); err != nil {
				return err
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

	// An organization named like the domain (OWASP for owasp.org,
	// Utica Products for uticaproducts.com) is tied when it is tied some other way, or when it
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
		// small networks (a company's many /24s) have no one network serving
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

// familySmallBlocks bounds the small networks classified for one
// organization whose names are spread over them.
const familySmallBlocks = 10

// blocksToClassify returns the networks serving enough of the domain's
// names, and, for a directly tied organization none of whose networks does
// (a company whose names are spread over small networks), up to
// familySmallBlocks of its networks, so the other domains they serve are
// found too.
func (s *familySearch) blocksToClassify(direct map[string][]string) []string {
	blocks := s.servingBlocks()
	serving := map[string]bool{}
	for _, b := range blocks {
		for _, h := range s.holders[b] {
			serving[h] = true
		}
	}

	byNames := make([]string, 0, len(s.netNames))
	for b := range s.netNames {
		byNames = append(byNames, b)
	}

	sort.Slice(byNames, func(i, j int) bool {
		if s.netNames[byNames[i]] != s.netNames[byNames[j]] {
			return s.netNames[byNames[i]] > s.netNames[byNames[j]]
		}

		return byNames[i] < byNames[j]
	})

	added := map[string]int{}
	for _, b := range byNames {
		if s.netNames[b] >= s.rules.MinHostedNames {
			continue
		}
		for _, h := range s.holders[b] {
			if len(direct[h]) > 0 && !serving[h] && added[h] < familySmallBlocks {
				added[h]++
				blocks = append(blocks, b)
				break
			}
		}
	}

	return blocks
}

// domainLabel is the label of a domain's registered name before its public
// suffix: uticaproductsus for www.uticaproductsus.com.
func domainLabel(domain string) string {
	label, _, _ := strings.Cut(graph.RegisteredDomain(domain), ".")
	return label
}

// namedLike reports whether one of an organization's names is the domain
// label's (semantics.OrgNameMatchesLabel).
func (s *familySearch) namedLike(p *familyProfile, label string) bool {
	for b := range p.brands {
		if semantics.OrgNameMatchesLabel(strings.Fields(b), label) {
			return true
		}
	}
	for _, n := range p.names {
		if semantics.OrgNameMatchesLabel(graph.AddressWords(n), label) {
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
	for _, b := range s.blocksToClassify(direct) {
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
		holderDomains := map[string]bool{}
		for _, h := range s.holders[b] {
			if len(direct[h]) > 0 || kin[h] {
				held = true
			}
			if p := s.profiles[h]; p != nil {
				for dom := range p.registers {
					holderDomains[graph.RegisteredDomain(dom)] = true
				}
			}
		}

		// A network whose holder has no tie of its own to the domain is not
		// the domain's when an unrelated registered domain has at least as
		// many of its stored names: a hosting provider's network serving
		// several customers is not any one customer's, however few names
		// were stored for it.
		rival := false
		for dom, n := range d {
			if !domains[dom] && !holderDomains[dom] && n >= d[domain] {
				rival = true
			}
		}

		byShare := (share >= s.rules.DedicatedShare || familyShare >= s.rules.DedicatedShare) && !rival

		net := FamilyNetwork{CIDR: s.cidrs[b], Names: s.netNames[b], Share: share, Dedicated: held || byShare}
		if hs := s.holders[b]; len(hs) > 0 {
			if p, ok := s.profiles[hs[0]]; ok {
				net.Holder, net.HolderID = graph.AssetLabel(p.asset), p.asset.ID
			}
		}

		s.report.Networks = append(s.report.Networks, net)
		if net.Dedicated {
			dedicated[b] = true
		}
	}

	return dedicated, sampled, nil
}

// memberNetworks marks the networks held by the institution itself (a
// same-institution member or a department) as the family's, however few of
// the names stored for them are the domain's: a company's network serving
// owaspfdn.org and its other domains is not a provider's.
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
			if name := graph.ContentString(a, "name"); name != "" && !reverseLookupName(a) {
				out[graph.RegisteredDomain(name)]++
				total++
			}
		}
	}

	return out, total, nil
}
