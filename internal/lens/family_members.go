// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"sort"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// kin returns the organizations whose networks are the domain's although
// they are not tied to it directly, and the registered domains whose names
// count with the domain's on a network. The seeds are the domain's
// registrants and the organizations named like it; kin are the
// organizations whose names are variants of a seed's (OWASP Foundation
// Systems Corporation for OWASP Foundation), and the domains are the ones
// the seeds and kin registered (owasp.org and owaspfoundation.org for
// owaspfdn.org). A company's network serving several of its domains
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
			domains[graph.RegisteredDomain(d)] = true
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

// relatedDomains lists the other registered domains on dedicated networks
// held by the family's members.
func (s *familySearch) relatedDomains(domain string, dedicated map[string]bool, sampled map[string]map[string]int) {
	family, own := map[string]bool{}, map[string]bool{}
	for _, m := range s.report.Members {
		if m.Relation != FamilyOther {
			family[m.Organization.ID] = true
		}
		if m.Relation == FamilySame || m.Relation == FamilyDepartment {
			own[m.Organization.ID] = true
		}
	}

	related := map[string]*RelatedDomain{}
	for b := range dedicated {
		held, mine := false, false
		for _, h := range s.holders[b] {
			held = held || family[h]
			mine = mine || own[h]
		}
		if !held {
			continue
		}

		for d, n := range sampled[b] {
			if d == domain {
				continue
			}

			r, ok := related[d]
			if !ok || n > r.Names {
				related[d] = &RelatedDomain{Domain: d, Names: n, CIDR: s.cidrs[b],
					OwnNetwork: mine || (ok && r.OwnNetwork)}
			} else if mine {
				r.OwnNetwork = true
			}
		}
	}

	for d, r := range related {
		if !r.OwnNetwork {
			continue
		}

		label := domainLabel(d)
		for id := range own {
			p := s.profiles[id]
			if p.registers[d] || s.namedLike(p, label) {
				r.Own = true
				break
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

	s.tied = map[string]bool{}
	for id := range ties {
		s.tied[id] = true
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

	// A unit recorded under a shorter name (Security Testing Laboratory
	// for OWASP Security Testing Laboratory) is the same department.
	for i, m := range s.report.Members {
		p := s.profiles[m.Organization.ID]
		if m.Relation != FamilyOther || (!s.hasUnitWord(p) && !s.endsInUnitNoun(p)) {
			continue
		}
		for _, d := range s.report.Members {
			if d.Relation == FamilyDepartment && s.variantOf(p, s.profiles[d.Organization.ID]) {
				s.report.Members[i].Relation = FamilyDepartment
				s.report.Members[i].Evidence = append(s.report.Members[i].Evidence,
					"another name of the department "+graph.AssetLabel(d.Organization))
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
