// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensConcentration asks which providers a domain or organization depends on
// so heavily that their failure would take it down.
const LensConcentration = "concentration"

var concentrationLens = SubjectLens{
	Name:    LensConcentration,
	Command: "concentration",
	Description: "Show how much a domain or organization relies on single providers for DNS, registration, " +
		"certificates, hosting and mail, and which are single points of failure. Read-only",
	Examples: []string{"What breaks for <domain> if one provider goes down?",
		"Is <organization>'s DNS concentrated on one provider?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindConcentration(ctx, g, schema, root, opts.Limits)
	},
}

// Concentration levels.
const (
	ConcentrationSingle    = "single_point_of_failure"
	ConcentrationDominant  = "concentrated"
	ConcentrationDiverse   = "diverse"
	ConcentrationOwn       = "own"
	ConcentrationFew       = "too_few"
	concentrationProviders = 5
)

// Concentration is how one category of dependency is spread over providers.
type Concentration struct {
	Category  string        `json:"category"`
	Unit      string        `json:"unit"`
	Total     int           `json:"total"`
	Providers []ChangeGroup `json:"providers"`
	TopShare  float64       `json:"top_share"`
	Level     string        `json:"level"`
}

// ConcentrationReport is the result of the concentration lens.
type ConcentrationReport struct {
	lensBase
	Categories []Concentration `json:"categories"`
}

var concentrationJSON = semantics.File("concentration.json")

type concentrationRules struct {
	License       string   `json:"_license"`
	About         string   `json:"_about"`
	DominantShare float64  `json:"dominant_share"`
	MinItems      int      `json:"min_items"`
	OwnLabels     []string `json:"own_labels"`
}

var loadConcentrationRules = sync.OnceValue(func() concentrationRules {
	var r concentrationRules
	if err := graph.DecodeStrict(concentrationJSON, &r); err != nil {
		panic("concentration.json: " + err.Error())
	}
	if r.DominantShare <= 0 || r.DominantShare > 1 {
		panic("concentration.json: dominant_share must be in (0, 1]")
	}

	return r
})

// FindConcentration reports how the dependencies of a domain or
// organization are spread over providers, from the domains, certificates,
// network and email lenses. It reads only.
func FindConcentration(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (ConcentrationReport, error) {
	// The lenses this one builds on walk the same footprint; read it once.
	g = graph.Cached(g)
	var out ConcentrationReport
	domains, err := FindDomains(ctx, g, schema, root, limits)
	if err != nil {
		return out, err
	}
	certs, err := FindCertificates(ctx, g, schema, root, limits)
	if err != nil {
		return out, err
	}
	network, err := FindNetworkInfrastructure(ctx, g, schema, root, limits)
	if err != nil {
		return out, err
	}
	mail, err := FindEmailSecurity(ctx, g, schema, root, limits)
	if err != nil {
		return out, err
	}

	var hosting []ChangeGroup
	for _, h := range network.Hosting {
		key := h.Party
		if h.Own {
			key = ConcentrationOwn
		}
		hosting = append(hosting, ChangeGroup{Key: key, Count: h.Names, Examples: h.Examples})
	}

	out.lensBase = domains.lensBase
	for _, p := range []lensBase{certs.lensBase, mail.lensBase} {
		out.Reads += p.Reads
		if p.Truncated && !out.Truncated {
			out.Truncated, out.Reason = true, p.Reason
		}
	}
	out.Reads += network.Reads
	if network.Truncated && !out.Truncated {
		out.Truncated, out.Reason = true, network.Reason
	}

	for _, c := range []struct {
		category, unit string
		groups         []ChangeGroup
	}{
		{"DNS providers", "domain(s)", domains.DNS},
		{"registrars", "domain(s)", domains.Registrars},
		{"certificate authorities", "certificate(s)", certs.Issuers},
		{"hosting", "name(s)", hosting},
		{"mail providers", "domain(s)", mail.Providers},
	} {
		if conc, ok := concentrationOf(c.category, c.unit, c.groups); ok {
			out.Categories = append(out.Categories, conc)
		}
	}
	return out, nil
}

// concentrationOf measures one category. Shares are of the items counted;
// an item served by two providers counts for both.
func concentrationOf(category, unit string, groups []ChangeGroup) (Concentration, bool) {
	rules := loadConcentrationRules()
	c := Concentration{Category: category, Unit: unit}
	var outside []ChangeGroup
	for _, g := range groups {
		c.Total += g.Count
		if !slices.Contains(rules.OwnLabels, g.Key) {
			outside = append(outside, g)
		}
	}
	if c.Total == 0 {
		return c, false
	}

	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Count > groups[j].Count })
	c.Providers = groups[:min(concentrationProviders, len(groups))]
	if len(outside) == 0 {
		c.Level, c.TopShare = ConcentrationOwn, 1
		return c, true
	}

	// The subject's own infrastructure is never a concern: the shares are
	// of what outside providers serve.
	sort.SliceStable(outside, func(i, j int) bool { return outside[i].Count > outside[j].Count })
	served := 0
	for _, g := range outside {
		served += g.Count
	}
	c.TopShare = float64(outside[0].Count) / float64(served)
	switch {
	case served < rules.MinItems:
		c.Level = ConcentrationFew
	case len(outside) == 1:
		c.Level = ConcentrationSingle
	case c.TopShare >= rules.DominantShare:
		c.Level = ConcentrationDominant
	default:
		c.Level = ConcentrationDiverse
	}
	return c, true
}

// Text implements Report.
func (r ConcentrationReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Provider concentration of %s (%d reads).\n", subject, r.Reads)
	if len(r.Categories) == 0 {
		b.WriteString("No provider of DNS, registration, certificates, hosting or mail is stored.\n")
	}

	levels := map[string]string{ConcentrationSingle: "SINGLE POINT OF FAILURE", ConcentrationDominant: "concentrated",
		ConcentrationDiverse: "spread", ConcentrationOwn: "all its own",
		ConcentrationFew: "too little stored to judge"}
	for _, c := range r.Categories {
		if c.Level == ConcentrationOwn || c.Level == ConcentrationFew {
			fmt.Fprintf(&b, "\n%s: %s (%d %s).\n", c.Category, levels[c.Level], c.Total, c.Unit)
		} else {
			fmt.Fprintf(&b, "\n%s: %s; the largest outside provider serves %.0f%% of what outside providers serve "+
				"(%d %s in all).\n", c.Category, levels[c.Level], 100*c.TopShare, c.Total, c.Unit)
		}
		for _, p := range c.Providers {
			fmt.Fprintf(&b, "  %s: %d\n", p.Key, p.Count)
		}
	}

	b.WriteString("\nShares count what is stored; an item served by two providers counts for both." +
		r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r ConcentrationReport) Facts() []string {
	var out []string
	for _, c := range r.Categories {
		if len(c.Providers) > 0 {
			out = append(out, fmt.Sprintf("%s %s %s", c.Category, c.Level, c.Providers[0].Key))
		}
	}
	return out
}
