// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

func (s *dupSearch) truncate(reason string) {
	truncateOnce(&s.report.Truncated, &s.report.Reason, reason)
}

// edges reads an asset's edges completely, a page at a time. A read a store
// that cannot page cut short marks the report partial rather than silently
// dropping evidence.
func (s *dupSearch) edges(id, dir, label string) ([]graph.Relation, error) {
	edges, more, err := graph.ReadEdges(s.ctx, s.graph, id, dir, label, 0, s.spend)
	if err == nil && more {
		s.truncate(partialRead(id, dir, label))
	}

	return edges, err
}

// labelEdges reads an asset's edges for several labels in one direction
// as edges does for each, with every label's first edges in one read when
// the graph can.
func (s *dupSearch) labelEdges(id, dir string, labels []string) (map[string][]graph.Relation, error) {
	byLabel, more, err := graph.ReadLabels(s.ctx, s.graph, id, dir, labels, 0, s.spend)
	if err != nil {
		return nil, err
	}
	for _, label := range labels {
		if more[label] {
			s.truncate(partialRead(id, dir, label))
		}
	}

	return byLabel, nil
}

// firstEdges reads at most limit edges in one bounded read, for samples
// that are meant to be partial (a domain's names, a network's addresses).
func (s *dupSearch) firstEdges(id, dir, label string, limit int) ([]graph.Relation, error) {
	s.spend()
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

// spend counts one database read; the search has no read budget.
func (s *dupSearch) spend() bool {
	s.report.Reads++
	return true
}

func (s *dupSearch) asset(id string) (graph.Asset, error) {
	if a, ok := s.batch.get(id); ok {
		return a, nil
	}

	s.report.Reads++
	return s.graph.GetAsset(s.ctx, id)
}

// profile reads an organization's names, identifiers, contact records,
// addresses and corporate links.
func (s *dupSearch) profile(o graph.Asset) (*orgProfile, error) {
	p := &orgProfile{asset: o, brands: map[string]bool{}, ids: map[string]map[string]bool{},
		contacts: map[string]bool{}, locations: map[string]bool{}, addresses: map[string]bool{},
		related: map[string]bool{}, parents: map[string]bool{}, idEdges: map[string][]string{},
		contactEdges: map[string][]string{}}
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

		if t, v, ok := p.addIdentifier(graph.ContentString(a, "id_type"), graph.ContentString(a, "id")); ok {
			p.idEdges[t+"\x00"+v] = append(p.idEdges[t+"\x00"+v], e.ID)
		}
	}

	byLabel, err := s.labelEdges(o.ID, "out", locationLabels)
	if err != nil {
		return nil, err
	}
	for _, label := range locationLabels {
		locs := byLabel[label]
		for _, e := range locs {
			p.locations[e.ToID] = true
		}
	}

	crs, err := s.edges(o.ID, "in", "organization")
	if err != nil {
		return nil, err
	}
	for _, e := range crs {
		p.contacts[e.FromID] = true
		p.contactEdges[e.FromID] = append(p.contactEdges[e.FromID], e.ID)

		locs, err := s.edges(e.FromID, "out", "street_address")
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
	// every address counts toward the evidence that picks a merge's survivor
	stored := len(p.locations)
	for id := range p.locations {
		// a registered agent's or office tower's address is not compared
		if crowded, err := s.crowdedLocation(id); err != nil {
			return nil, err
		} else if crowded {
			delete(p.locations, id)
			continue
		}

		loc, err := s.asset(id)
		if err != nil {
			return nil, err
		}
		if k := graph.StreetAddressKey(loc); k != "" {
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
					p.parents[other] = true
				}

				p.related[other] = true
			}
		}
	}

	p.evidence = len(ids) + len(crs) + stored + len(p.related)
	if err := s.attachDocuments(p); err != nil {
		return nil, err
	}
	return p, nil
}

// documentLinks reads, once per search, what documents state relates
// organizations: former names and mergers, parents and units.
func (s *dupSearch) documentLinks() (docLinks, error) {
	if s.linksRead {
		return s.links, nil
	}
	s.linksRead = true
	findings, err := documentFindings(s.ctx, s.graph,
		append(append([]string{}, docFormerPredicates...), docParentPredicates...))
	if err != nil {
		return nil, err
	}
	s.links = buildDocLinks(findings)
	return s.links, nil
}

// attachDocuments records on a profile what documents state relates it to
// other organizations, matched exactly by its names.
func (s *dupSearch) attachDocuments(p *orgProfile) error {
	links, err := s.documentLinks()
	if err != nil || len(links) == 0 {
		return err
	}
	for _, n := range p.names {
		for other, l := range links[docFold(n)] {
			if p.docs == nil {
				p.docs = map[string]*docLink{}
			}
			p.docs[other] = l
		}
	}
	return nil
}

// docLinkTo returns what documents state relates a to one of b's names.
func docLinkTo(a, b *orgProfile) *docLink {
	if len(a.docs) == 0 {
		return nil
	}
	for _, n := range b.names {
		if l, ok := a.docs[docFold(n)]; ok {
			return l
		}
	}
	return nil
}

func (p *orgProfile) addName(name string) {
	name = strings.TrimSpace(name)
	if name == "" || slices.Contains(p.names, name) {
		return
	}

	p.names = append(p.names, name)
	if b := semantics.OrgNameKey(name); b != "" {
		p.brands[b] = true
	}
}

// addIdentifier records an identifier and returns its normalized type and
// value; ok is false for none, or for a name, which is recorded as one.
func (p *orgProfile) addIdentifier(idtype, value string) (string, string, bool) {
	idtype = strings.ToLower(strings.TrimSpace(idtype))
	value = strings.TrimSpace(value)
	if idtype == "" || value == "" {
		return "", "", false
	}

	switch idtype {
	case "org_name", "legal_name":
		p.addName(value)
		return "", "", false
	case "registration_id":
		value = normRegistration(value)
	default:
		value = strings.ToLower(value)
	}

	if p.ids[idtype] == nil {
		p.ids[idtype] = map[string]bool{}
	}

	p.ids[idtype][value] = true
	return idtype, value, true
}

func normRegistration(s string) string {
	return strings.ToUpper(strings.Join(strings.Fields(s), ""))
}
