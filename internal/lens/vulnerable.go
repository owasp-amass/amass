// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/vuln"
)

// LensVulnerable asks which identified software of a domain or organization
// has known vulnerabilities.
const LensVulnerable = "vulnerable_software"

var vulnerableLens = SubjectLens{
	Name:    LensVulnerable,
	Command: "vulnerable",
	Description: "List the software versions identified on what a domain or organization controls that NVD " +
		"says have vulnerabilities, known exploited ones (CISA KEV) first. Matched by version; read-only",
	Examples: []string{"Does <domain> run software with known vulnerabilities?",
		"Which of <organization>'s servers run software with exploited CVEs?",
		"What CVEs affect the software on <domain>?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindVulnerable(ctx, g, schema, root, opts.Limits)
	},
}

// VulnDataPath returns the vulnerability data file the lens reads; tests
// replace it.
var VulnDataPath = vuln.DefaultPath

// vulnerableExamples is how many CVEs a finding's text names.
const vulnerableExamples = 5

// VulnerableSoftware is one identified product version with CVEs.
type VulnerableSoftware struct {
	Product   string       `json:"product"`
	Version   string       `json:"version"`
	Endpoints []string     `json:"endpoints"`
	CVEs      []vuln.Match `json:"cves"`
	KEV       int          `json:"kev"`
}

// UncheckedSoftware is an identified product version that could not be
// checked, and why.
type UncheckedSoftware struct {
	Product   string      `json:"product"`
	Version   string      `json:"version,omitempty"`
	Status    vuln.Status `json:"status"`
	Reason    string      `json:"reason"`
	Endpoints int         `json:"endpoints"`
}

// VulnerableReport is the result of the vulnerable software lens.
type VulnerableReport struct {
	Root      graph.Asset          `json:"root"`
	Owners    []string             `json:"owners,omitempty"`
	Footprint int                  `json:"footprint"`
	Services  int                  `json:"services"`
	Reads     int                  `json:"reads"`
	Truncated bool                 `json:"truncated"`
	Reason    string               `json:"reason,omitempty"`
	DataPath  string               `json:"data_path"`
	UpdatedAt time.Time            `json:"data_updated,omitzero"`
	Software  []VulnerableSoftware `json:"software"`
	Clean     []string             `json:"clean,omitempty"`
	Unchecked []UncheckedSoftware  `json:"unchecked,omitempty"`
}

// FindVulnerable checks the software the services lens identifies on root's
// controlled footprint against the local vulnerability data. It reads only.
func FindVulnerable(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (VulnerableReport, error) {
	out := VulnerableReport{Root: root, DataPath: VulnDataPath()}
	services, err := FindServices(ctx, g, schema, root, limits)
	if err != nil {
		return out, err
	}

	out.Owners, out.Footprint, out.Services = services.Owners, services.Footprint, len(services.Services)
	out.Reads, out.Truncated, out.Reason = services.Reads, services.Truncated, services.Reason

	data, err := vuln.Load(out.DataPath)
	if err != nil {
		return out, fmt.Errorf("vulnerability data %s: %w", out.DataPath, err)
	}

	out.UpdatedAt = data.UpdatedAt

	type key struct{ product, version string }
	endpoints := map[key][]string{}
	var order []key
	for _, s := range services.Services {
		for _, p := range s.Identified {
			k := key{p.Product, p.Version}
			if _, ok := endpoints[k]; !ok {
				order = append(order, k)
			}

			list := endpoints[k]
			for _, e := range s.Endpoints {
				graph.AddUnique(&list, e)
			}

			endpoints[k] = list
		}
	}

	for _, a := range services.Applications {
		ids := a.Identified
		if !slices.ContainsFunc(ids, func(p IdentifiedProduct) bool { return p.Product == a.Product }) {
			ids = append(ids, IdentifiedProduct{Product: a.Product})
		}
		for _, p := range ids {
			k := key{p.Product, p.Version}
			if _, ok := endpoints[k]; !ok {
				order = append(order, k)
			}

			list := endpoints[k]
			graph.AddUnique(&list, a.Site)
			endpoints[k] = list
		}
	}

	for _, k := range order {
		matches, status, reason := data.Check(k.product, k.version)
		label := strings.TrimSpace(k.product + " " + k.version)
		switch {
		case status != vuln.Checked:
			out.Unchecked = append(out.Unchecked, UncheckedSoftware{Product: k.product, Version: k.version,
				Status: status, Reason: reason, Endpoints: len(endpoints[k])})
		case len(matches) == 0:
			out.Clean = append(out.Clean, label)
		default:
			v := VulnerableSoftware{Product: k.product, Version: k.version, Endpoints: endpoints[k], CVEs: matches}
			for _, m := range matches {
				if m.KEV {
					v.KEV++
				}
			}

			out.Software = append(out.Software, v)
		}
	}

	// Add-ons are listed, not checked: their asset versions are not
	// confirmed releases, and they have no catalog entries.
	addons := map[string][]string{}
	sites := map[string]int{}
	for _, a := range services.Applications {
		sites[a.Product]++
		list := addons[a.Product]
		for _, c := range a.Components {
			graph.AddUnique(&list, c.Kind+" "+c.Name)
		}
		if len(list) > 0 {
			addons[a.Product] = list
		}
	}
	for _, product := range slices.Sorted(maps.Keys(addons)) {
		names := addons[product]
		sort.Strings(names)
		shown := names[:min(len(names), vulnerableExamples*2)]
		reason := fmt.Sprintf("%d found (%s", len(names), strings.Join(shown, ", "))
		if len(names) > len(shown) {
			reason += fmt.Sprintf(", and %d more", len(names)-len(shown))
		}

		reason += "); their versions in asset URLs are chosen by each add-on, so they are not confirmed"
		out.Unchecked = append(out.Unchecked, UncheckedSoftware{Product: product + " add-ons", Status: vuln.Unchecked,
			Reason: reason, Endpoints: sites[product]})
	}

	sort.SliceStable(out.Software, func(i, j int) bool {
		a, b := out.Software[i], out.Software[j]
		if a.KEV != b.KEV {
			return a.KEV > b.KEV
		}

		return topScore(a) > topScore(b)
	})
	return out, nil
}

func topScore(v VulnerableSoftware) float64 {
	if len(v.CVEs) == 0 {
		return 0
	}

	return v.CVEs[0].Score
}

// Text implements Report.
func (r VulnerableReport) Text() string {
	var b strings.Builder
	scope := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		scope += " and " + strings.Join(r.Owners, ", ")
	}

	kev := 0
	for _, s := range r.Software {
		if s.KEV > 0 {
			kev++
		}
	}

	fmt.Fprintf(&b, "Vulnerable software of %s: %d identified version(s) with CVEs, %d with known exploited ones, "+
		"from %d service(s) (%d reads).\n", scope, len(r.Software), kev, r.Services, r.Reads)
	if r.UpdatedAt.IsZero() {
		fmt.Fprintf(&b, "\nNo vulnerability data at %s: run `amass vuln-update` to fetch it.\n", r.DataPath)
	} else {
		fmt.Fprintf(&b, "Vulnerability data updated %s.\n", r.UpdatedAt.Format(time.DateOnly))
	}

	for _, s := range r.Software {
		where := strings.Join(s.Endpoints[:min(3, len(s.Endpoints))], ", ")
		if len(s.Endpoints) > 3 {
			where += fmt.Sprintf(" and %d more", len(s.Endpoints)-3)
		}

		fmt.Fprintf(&b, "\n%s %s on %s: %d CVE(s)", s.Product, s.Version, where, len(s.CVEs))
		if s.KEV > 0 {
			fmt.Fprintf(&b, ", %d known exploited", s.KEV)
		}

		b.WriteString("\n")
		for i, m := range s.CVEs {
			if i == vulnerableExamples {
				fmt.Fprintf(&b, "  ... and %d more\n", len(s.CVEs)-i)
				break
			}

			fmt.Fprintf(&b, "  %s", m.CVE)
			if m.Score > 0 {
				fmt.Fprintf(&b, " %.1f %s", m.Score, m.Severity)
			}
			if m.KEV {
				fmt.Fprintf(&b, "; known exploited (CISA KEV since %s): %s", m.KEVAdded, m.KEVName)
			}

			fmt.Fprintf(&b, " https://nvd.nist.gov/vuln/detail/%s\n", m.CVE)
		}
	}

	if len(r.Clean) > 0 {
		fmt.Fprintf(&b, "\nNo CVEs for: %s\n", strings.Join(r.Clean, ", "))
	}
	if len(r.Unchecked) > 0 {
		b.WriteString("\nNot checked:\n")
		for _, u := range r.Unchecked {
			fmt.Fprintf(&b, "  %s on %d endpoint(s): %s\n", strings.TrimSpace(u.Product+" "+u.Version), u.Endpoints,
				u.Reason)
		}
	}

	b.WriteString("\nMatched by the version in stored headers, banners and asset URLs: distributions often " +
		"backport fixes without changing the version, and software can hide or fake it, so confirm with the " +
		"vendor's advisory. CVE data from the NVD; known exploited vulnerabilities from CISA's KEV catalog.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s); raise -max-assets or -max-reads to cover more.", r.Reason)
	}

	b.WriteString("\n")
	return b.String()
}

// Facts implements Report: "kev" for each known exploited CVE and "cve"
// for the others, with the product version.
func (r VulnerableReport) Facts() []string {
	var out []string
	for _, s := range r.Software {
		for _, m := range s.CVEs {
			kind := "cve"
			if m.KEV {
				kind = "kev"
			}

			out = append(out, fmt.Sprintf("%s %s %s %s", kind, m.CVE, s.Product, s.Version))
		}
	}

	return out
}

// Partial implements Report.
func (r VulnerableReport) Partial() (bool, string) { return r.Truncated, r.Reason }
