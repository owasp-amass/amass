// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensCoverage asks how complete the stored data about a domain or
// organization is.
const LensCoverage = "coverage"

var coverageLens = SubjectLens{
	Name:    LensCoverage,
	Command: "coverage",
	Description: "Show how complete the stored data about a domain or organization is: assets by type, " +
		"unresolved names, missing registrations, stale assets, and what collection would fill each gap. Read-only",
	Examples: []string{"How complete is our data on <domain>?", "What is missing about <organization>?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindCoverage(ctx, g, schema, root, opts.Limits)
	},
}

// CoverageGap is one kind of missing data.
type CoverageGap struct {
	Name     string   `json:"name"`
	Missing  int      `json:"missing"`
	Of       int      `json:"of"`
	Examples []string `json:"examples"`
	Fill     string   `json:"fill"`
}

// CoverageReport is the result of the coverage lens.
type CoverageReport struct {
	lensBase
	ByType map[string]int `json:"by_type"`
	Gaps   []CoverageGap  `json:"gaps"`
}

var coverageJSON = semantics.File("coverage.json")

type coverageRules struct {
	License             string            `json:"_license"`
	About               string            `json:"_about"`
	StaleDays           int               `json:"stale_days"`
	RegistrationPurpose string            `json:"registration_purpose"`
	Gaps                map[string]string `json:"gaps"`
}

var loadCoverageRules = sync.OnceValue(func() coverageRules {
	var r coverageRules
	if err := graph.DecodeStrict(coverageJSON, &r); err != nil {
		panic("coverage.json: " + err.Error())
	}
	for _, g := range []string{"names_without_records", "domains_without_registration",
		"netblocks_without_registration", "addresses_without_netblock", "stale_assets"} {
		if r.Gaps[g] == "" {
			panic("coverage.json: gaps." + g + " is required")
		}
	}

	return r
})

const coverageExamples = 5

// FindCoverage walks the controlled footprint of a domain or organization
// and reports what is stored about it and what is missing. It reads only.
func FindCoverage(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (CoverageReport, error) {
	out := CoverageReport{ByType: map[string]int{}}
	s, err := newScope(ctx, g, schema, root, limits, "coverage")
	if err != nil {
		return out, err
	}

	rules := loadCoverageRules()
	gaps := map[string]*CoverageGap{}
	for name, fill := range rules.Gaps {
		gaps[name] = &CoverageGap{Name: name, Fill: fill}
	}
	miss := func(name, example string) {
		g := gaps[name]
		g.Missing++
		if len(g.Examples) < coverageExamples {
			g.Examples = append(g.Examples, example)
		}
	}

	latest := root.LastSeen
	for _, o := range s.owners {
		if o.LastSeen.After(latest) {
			latest = o.LastSeen
		}
	}
	staleBefore := latest.Add(-time.Duration(rules.StaleDays) * 24 * time.Hour)
	domains := map[string]graph.Asset{}
	for _, id := range s.order {
		a := s.owned[id]
		out.ByType[a.Type]++
		gaps["stale_assets"].Of++
		if !latest.IsZero() && !a.LastSeen.IsZero() && a.LastSeen.Before(staleBefore) {
			miss("stale_assets", fmt.Sprintf("%s %s (last seen %s)", a.Type, graph.AssetLabel(a),
				a.LastSeen.Format("2006-01-02")))
		}
		if a.Type == "FQDN" {
			if d := graph.RegisteredDomain(graph.FQDNName(a)); d != "" && !reservedName(d) {
				if _, ok := domains[d]; !ok || graph.FQDNName(a) == d {
					domains[d] = a
				}
			}
		}
	}

	for _, id := range s.order {
		if s.spent() {
			break
		}
		a := s.owned[id]
		switch a.Type {
		case "FQDN":
			gaps["names_without_records"].Of++
			records, err := recordTypesOf(s.w, a)
			if err != nil {
				return out, err
			}
			if len(records) == 0 {
				miss("names_without_records", graph.FQDNName(a))
			}
		case "Netblock", "IPAddress":
			steps, err := s.w.steps(a)
			if err != nil {
				return out, err
			}
			has := false
			for _, st := range steps {
				if a.Type == "Netblock" && st.forward && st.purpose == rules.RegistrationPurpose {
					has = true
				}
				if a.Type == "IPAddress" && !st.forward && st.other.Type == "Netblock" {
					has = true
				}
			}
			gap := "netblocks_without_registration"
			if a.Type == "IPAddress" {
				gap = "addresses_without_netblock"
			}
			gaps[gap].Of++
			if !has {
				miss(gap, graph.AssetLabel(a))
			}
		}
	}

	domainRules := loadDomainRules()
	keys := make([]string, 0, len(domains))
	for d := range domains {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	for _, d := range keys {
		if s.spent() {
			break
		}
		gaps["domains_without_registration"].Of++
		name := domains[d]
		if graph.FQDNName(name) != d {
			name = graph.Asset{}
		}
		if _, ok, err := s.registrationOf(name, d, domainRules); err != nil {
			return out, err
		} else if !ok {
			miss("domains_without_registration", d)
		}
	}

	out.lensBase = s.base()
	for _, g := range gaps {
		if g.Of > 0 {
			out.Gaps = append(out.Gaps, *g)
		}
	}
	sort.Slice(out.Gaps, func(i, j int) bool {
		a, b := out.Gaps[i], out.Gaps[j]
		if a.Missing != b.Missing {
			return a.Missing > b.Missing
		}
		return a.Name < b.Name
	})
	return out, nil
}

// Text implements Report.
func (r CoverageReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Data coverage of %s: %d controlled asset(s) (%d reads).\n", subject, r.Footprint, r.Reads)

	types := make([]string, 0, len(r.ByType))
	for t := range r.ByType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		if r.ByType[types[i]] != r.ByType[types[j]] {
			return r.ByType[types[i]] > r.ByType[types[j]]
		}
		return types[i] < types[j]
	})
	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s %d", t, r.ByType[t]))
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, "By type: %s.\n", strings.Join(parts, ", "))
	}

	for _, g := range r.Gaps {
		title := strings.ReplaceAll(g.Name, "_", " ")
		fmt.Fprintf(&b, "\n%s: %d of %d (%.0f%%).", title, g.Missing, g.Of, 100*float64(g.Missing)/float64(g.Of))
		if g.Missing == 0 {
			b.WriteString("\n")
			continue
		}
		fmt.Fprintf(&b, " %s\n  e.g. %s\n", g.Fill, strings.Join(g.Examples, "; "))
	}

	b.WriteString("\nCoverage is of what the enumerations reached; assets they never found are not counted." +
		r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r CoverageReport) Facts() []string {
	var out []string
	for _, g := range r.Gaps {
		out = append(out, fmt.Sprintf("%s %d of %d", g.Name, g.Missing, g.Of))
	}
	return out
}
