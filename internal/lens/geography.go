// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensGeography asks where a domain or organization and its hosting are.
const LensGeography = "geography"

var geographyLens = SubjectLens{
	Name:    LensGeography,
	Command: "geography",
	Description: "Show where a domain or organization is: the countries of its stored addresses and registrations, " +
		"and the countries its hosting providers are registered in, by names hosted. Read-only",
	Examples: []string{"Which countries is <domain> hosted in?", "Where are <organization>'s offices registered?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindGeography(ctx, g, schema, root, opts.Limits)
	},
}

// GeographyReport is the result of the geography lens.
type GeographyReport struct {
	lensBase
	// Own counts the subject's stored locations by country; Hosting counts
	// the names hosted by parties registered in each country.
	Own     []ChangeGroup `json:"own"`
	Hosting []ChangeGroup `json:"hosting"`
}

var geographyJSON = semantics.File("geography.json")

type geographyRules struct {
	License       string   `json:"_license"`
	About         string   `json:"_about"`
	LocationTypes []string `json:"location_types"`
	CountryField  string   `json:"country_field"`
	CityField     string   `json:"city_field"`
	Unknown       string   `json:"unknown"`
	// PartyLocationPaths are the steps ("in organization") tried, in order,
	// from a hosting party with no location of its own.
	PartyLocationPaths [][]string `json:"party_location_paths"`
}

var loadGeographyRules = sync.OnceValue(func() geographyRules {
	var r geographyRules
	if err := graph.DecodeStrict(geographyJSON, &r); err != nil {
		panic("geography.json: " + err.Error())
	}
	if len(r.LocationTypes) == 0 || r.CountryField == "" || r.Unknown == "" {
		panic("geography.json: location_types, country_field and unknown are required")
	}
	for _, path := range r.PartyLocationPaths {
		for _, step := range path {
			if dir, label, ok := strings.Cut(step, " "); !ok || (dir != "in" && dir != "out") || label == "" {
				panic("geography.json: a party location step is a direction (in or out) and a label: " + step)
			}
		}
	}

	return r
})

// FindGeography reports the countries of a domain or organization's stored
// locations and of the parties hosting its names. It reads only.
func FindGeography(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (GeographyReport, error) {
	// The lenses this one builds on walk the same footprint; read it once.
	g = graph.Cached(g)
	var out GeographyReport
	s, err := newScope(ctx, g, schema, root, limits, "geography")
	if err != nil {
		return out, err
	}

	rules := loadGeographyRules()
	tally := changeTally{examples: 3, groups: map[string]map[string]*ChangeGroup{}}
	seen := map[string]bool{}
	for _, id := range s.order {
		if s.spent() {
			break
		}
		a := s.owned[id]
		locs, err := s.locations(a, rules)
		if err != nil {
			return out, err
		}
		for _, l := range locs {
			if key := a.ID + "\x00" + l.ID; !seen[key] {
				seen[key] = true
				tally.add("own", country(l, rules), placeLabel(a, l, rules))
			}
		}
	}

	network, err := FindNetworkInfrastructure(ctx, g, schema, root, limits)
	if err != nil {
		return out, err
	}
	var parties []string
	for _, h := range network.Hosting {
		if !h.Own && h.PartyID != "" {
			parties = append(parties, h.PartyID)
		}
	}
	read, _ := graph.AssetsByID(ctx, g, parties) // a party not read is read alone below
	hosting := map[string]*ChangeGroup{}
	var order []string
	for _, h := range network.Hosting {
		c := rules.Unknown
		if h.Own {
			c = "its own networks"
		} else if h.PartyID != "" {
			party, err := graph.AssetFrom(ctx, g, read, h.PartyID)
			if err == nil {
				if locs, err := s.locations(party, rules); err == nil && len(locs) > 0 {
					c = country(locs[0], rules)
				}
				if c == rules.Unknown {
					c = s.partyCountry(party, rules)
				}
			}
		}
		grp, ok := hosting[c]
		if !ok {
			grp = &ChangeGroup{Key: c}
			hosting[c] = grp
			order = append(order, c)
		}
		grp.Count += h.Names
		if len(grp.Examples) < 3 && !h.Own {
			graph.AddUnique(&grp.Examples, h.Party)
		}
	}
	for _, c := range order {
		out.Hosting = append(out.Hosting, *hosting[c])
	}
	slices.SortStableFunc(out.Hosting, func(a, b ChangeGroup) int { return b.Count - a.Count })

	out.lensBase = s.base()
	out.Reads += network.Reads
	if network.Truncated && !out.Truncated {
		out.Truncated, out.Reason = true, network.Reason
	}
	out.Own = tally.list("own")
	return out, nil
}

// locations returns the stored locations an asset names directly.
func (s *scope) locations(a graph.Asset, rules geographyRules) ([]graph.Asset, error) {
	steps, err := s.w.steps(a)
	if err != nil {
		return nil, err
	}
	var out []graph.Asset
	for _, st := range steps {
		if st.forward && slices.Contains(rules.LocationTypes, st.other.Type) {
			out = append(out, st.other)
		}
	}
	return out, nil
}

// partyLocationEdges bounds the edges read at each step of a party location
// path.
const partyLocationEdges = 20

// partyCountry follows the party location paths from a party and returns
// the country of the first location reached that has one.
func (s *scope) partyCountry(party graph.Asset, rules geographyRules) string {
	bounded, ok := s.w.graph.(graph.BoundedGraph)
	if !ok {
		return rules.Unknown
	}
	for _, path := range rules.PartyLocationPaths {
		frontier := []string{party.ID}
		for _, step := range path {
			dir, label, _ := strings.Cut(step, " ")
			var next []string
			for _, id := range frontier {
				if s.spent() {
					return rules.Unknown
				}
				s.report.Reads++
				edges, _, err := bounded.EdgesLimited(s.w.ctx, id, dir, label, time.Time{}, partyLocationEdges)
				if err != nil {
					break
				}
				for _, e := range edges {
					if dir == "out" {
						next = append(next, e.ToID)
					} else {
						next = append(next, e.FromID)
					}
				}
			}
			frontier = next
		}
		read, _ := graph.AssetsByID(s.w.ctx, s.w.graph, frontier)
		for _, id := range frontier {
			s.report.Reads++
			l, err := graph.AssetFrom(s.w.ctx, s.w.graph, read, id)
			if err == nil && slices.Contains(rules.LocationTypes, l.Type) {
				if c := country(l, rules); c != rules.Unknown {
					return c
				}
			}
		}
	}
	return rules.Unknown
}

func country(l graph.Asset, rules geographyRules) string {
	if c := strings.ToUpper(strings.TrimSpace(graph.ContentString(l, rules.CountryField))); c != "" {
		return c
	}
	return rules.Unknown
}

func placeLabel(a, l graph.Asset, rules geographyRules) string {
	label := graph.AssetLabel(a)
	if city := graph.ContentString(l, rules.CityField); city != "" {
		label += " (" + city + ")"
	}
	return label
}

// Text implements Report.
func (r GeographyReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Geography of %s, from %d controlled asset(s) (%d reads).\n", subject, r.Footprint, r.Reads)
	if len(r.Own) > 0 {
		b.WriteString("\nIts stored addresses, by country:\n")
		for _, c := range r.Own {
			fmt.Fprintf(&b, "  %s: %d, e.g. %s\n", c.Key, c.Count, strings.Join(c.Examples, "; "))
		}
	} else {
		b.WriteString("\nNo address of its own is stored.\n")
	}
	if len(r.Hosting) > 0 {
		b.WriteString("\nWhere the parties hosting its names are registered, by names hosted:\n")
		for _, c := range r.Hosting {
			fmt.Fprintf(&b, "  %s: %d name(s), e.g. %s\n", c.Key, c.Count, strings.Join(c.Examples, ", "))
		}
	}

	b.WriteString("\nRegistration addresses show where a party is registered, not where its servers run." +
		r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r GeographyReport) Facts() []string {
	var out []string
	for _, c := range r.Own {
		out = append(out, "located in "+c.Key)
	}
	for _, c := range r.Hosting {
		out = append(out, "hosted in "+c.Key)
	}
	return out
}
