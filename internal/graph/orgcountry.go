// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Organization country inference, shared by every tool and lens that needs to
// know where an organization is: the geography lens's primary-country
// conclusion and the on-demand, country-gated collectors (e.g. OCDS). It reads
// only and computes a conclusion from stored evidence; nothing is written
// (ai-design-principles.md, principle 10). The signals, their paths, fields,
// confidences and rationale are data in internal/semantics/org_country.json
// (principles 2 and 8), not code here.

const (
	// orgCountryStepEdges bounds the edges read at each step of a signal path.
	orgCountryStepEdges = 20
	// orgCountryFrontier bounds how many assets a signal path carries between
	// steps, so a highly connected organization cannot drive an unbounded walk.
	orgCountryFrontier = 50
)

// CountryEvidence is one country concluded for an organization, with the
// strongest signal that produced it and the asset that signal read.
type CountryEvidence struct {
	// Country is an ISO 3166-1 alpha-2 code.
	Country string `json:"country"`
	// Confidence is 0-100: the strongest contributing signal's confidence,
	// raised when more than one distinct signal agreed on the country.
	Confidence int `json:"confidence"`
	// Signal is the name of the strongest signal (from org_country.json).
	Signal string `json:"signal"`
	// Why is that signal's rationale, for evidence-cited answers.
	Why string `json:"why,omitempty"`
	// SourceID is the asset the country was read from (the organization itself
	// for the jurisdiction signal).
	SourceID string `json:"source_id,omitempty"`
	// Signals names every distinct signal that agreed on this country.
	Signals []string `json:"signals,omitempty"`
}

type orgCountrySignal struct {
	Name       string   `json:"name"`
	Path       []string `json:"path"`
	Field      string   `json:"field"`
	Form       string   `json:"form"`
	Confidence int      `json:"confidence"`
	Why        string   `json:"why"`
	Source     string   `json:"source"`
}

type orgCountryRules struct {
	License        string             `json:"_license"`
	About          string             `json:"_about"`
	AgreementBoost int                `json:"agreement_boost"`
	Signals        []orgCountrySignal `json:"signals"`
}

var orgCountryJSON = semantics.File("org_country.json")

var loadOrgCountryRules = sync.OnceValue(func() orgCountryRules {
	var r orgCountryRules
	if err := DecodeStrict(orgCountryJSON, &r); err != nil {
		panic("org_country.json: " + err.Error())
	}
	if len(r.Signals) == 0 {
		panic("org_country.json: at least one signal is required")
	}
	for _, sig := range r.Signals {
		if sig.Name == "" || sig.Field == "" {
			panic("org_country.json: a signal needs a name and a field")
		}
		if sig.Form != "jurisdiction" && sig.Form != "iso2" {
			panic("org_country.json: a signal form is 'jurisdiction' or 'iso2': " + sig.Form)
		}
		for _, step := range sig.Path {
			if dir, label, ok := strings.Cut(step, " "); !ok || (dir != "in" && dir != "out") || label == "" {
				panic("org_country.json: a path step is a direction (in or out) and a label: " + step)
			}
		}
	}
	return r
})

// OrgCountries returns the countries concluded for an organization, most
// credible first, each with the strongest signal that found it and the signals
// that agreed. It reads only, with bounded reads, so an unsupported repository
// or an unreadable organization simply yields fewer (or no) conclusions. limit
// bounds the countries returned (<=0 means all found).
func OrgCountries(ctx context.Context, g Graph, orgID string, limit int) ([]CountryEvidence, error) {
	if g == nil || strings.TrimSpace(orgID) == "" {
		return nil, nil
	}
	rules := loadOrgCountryRules()

	// agg accumulates, per country, the strongest signal seen and the set of
	// distinct signals that agreed.
	type agg struct {
		ev      CountryEvidence
		signals map[string]bool
	}
	byCountry := map[string]*agg{}

	for _, sig := range rules.Signals {
		ends, err := orgSignalAssets(ctx, g, orgID, sig.Path)
		if err != nil {
			return nil, err
		}
		for _, a := range ends {
			c := countryFromForm(sig.Form, ContentString(a, sig.Field))
			if c == "" {
				continue
			}
			e := byCountry[c]
			if e == nil {
				e = &agg{ev: CountryEvidence{Country: c}, signals: map[string]bool{}}
				byCountry[c] = e
			}
			e.signals[sig.Name] = true
			if sig.Confidence > e.ev.Confidence {
				e.ev.Confidence = sig.Confidence
				e.ev.Signal = sig.Name
				e.ev.Why = sig.Why
				e.ev.SourceID = a.ID
			}
		}
	}

	out := make([]CountryEvidence, 0, len(byCountry))
	for _, e := range byCountry {
		ev := e.ev
		if n := len(e.signals); n > 1 && rules.AgreementBoost > 0 {
			ev.Confidence = min(100, ev.Confidence+(n-1)*rules.AgreementBoost)
		}
		ev.Signals = sortedKeys(e.signals)
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Country < out[j].Country
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// OrgCountry returns the single most credible country for an organization, or
// ok=false when no country signal is present.
func OrgCountry(ctx context.Context, g Graph, orgID string) (CountryEvidence, bool, error) {
	cs, err := OrgCountries(ctx, g, orgID, 1)
	if err != nil || len(cs) == 0 {
		return CountryEvidence{}, false, err
	}
	return cs[0], true, nil
}

// orgSignalAssets returns the assets a signal path reaches from the
// organization. An empty path is the organization asset itself; otherwise each
// step is a bounded edge read in a direction along a label. It returns no
// assets (rather than an error) when the organization is unreadable, the
// repository is not edge-bounded, or the path reaches nothing.
func orgSignalAssets(ctx context.Context, g Graph, orgID string, path []string) ([]Asset, error) {
	if len(path) == 0 {
		a, err := g.GetAsset(ctx, orgID)
		if err != nil {
			return nil, nil
		}
		return []Asset{a}, nil
	}
	bounded, ok := g.(BoundedGraph)
	if !ok {
		return nil, nil
	}

	frontier := []string{orgID}
	for _, step := range path {
		dir, label, _ := strings.Cut(step, " ")
		var next []string
		seen := map[string]bool{}
		for _, id := range frontier {
			edges, _, err := bounded.EdgesLimited(ctx, id, dir, label, time.Time{}, orgCountryStepEdges)
			if err != nil {
				continue
			}
			for _, e := range edges {
				nid := e.ToID
				if dir == "in" {
					nid = e.FromID
				}
				if nid == "" || seen[nid] {
					continue
				}
				seen[nid] = true
				next = append(next, nid)
				if len(next) >= orgCountryFrontier {
					break
				}
			}
			if len(next) >= orgCountryFrontier {
				break
			}
		}
		if frontier = next; len(frontier) == 0 {
			return nil, nil
		}
	}

	read, _ := AssetsByID(ctx, g, frontier) // batched when supported; else read singly below
	out := make([]Asset, 0, len(frontier))
	for _, id := range frontier {
		a, err := AssetFrom(ctx, g, read, id)
		if err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// countryFromForm reads a country from a stored field per a signal's form,
// returning an ISO 3166-1 alpha-2 code or "".
func countryFromForm(form, raw string) string {
	switch form {
	case "jurisdiction":
		u := strings.ToUpper(strings.TrimSpace(raw))
		if i := strings.IndexByte(u, '-'); i > 0 {
			u = u[:i]
		}
		return iso2Code(u)
	case "iso2":
		return iso2Code(raw)
	default:
		return ""
	}
}

// iso2Code returns s uppercased when it is a two-letter ASCII country code,
// else "". A full country name some geocoders emit is rejected, because it
// would not match a publisher's or caller's ISO 3166-1 alpha-2 code.
func iso2Code(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) == 2 &&
		s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z' {
		return s
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
