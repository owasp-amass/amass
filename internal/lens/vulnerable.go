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

// VulnerableSoftware is one identified product version with CVEs. When
// its header or banner names its distribution and that distribution's
// data was read, CVEs holds those that still apply by that data, Update
// those a distribution update fixes, and Settled those the distribution
// says do not affect it or are fixed in its package.
type VulnerableSoftware struct {
	Product      string       `json:"product"`
	Version      string       `json:"version"`
	Distribution string       `json:"distribution,omitempty"`
	Package      string       `json:"package,omitempty"`
	Releases     []string     `json:"distribution_releases,omitempty"`
	DistroNote   string       `json:"distribution_note,omitempty"`
	Endpoints    []string     `json:"endpoints"`
	CVEs         []vuln.Match `json:"cves"`
	Update       []vuln.Match `json:"fixed_by_update,omitempty"`
	Settled      []vuln.Match `json:"settled,omitempty"`
	KEV          int          `json:"kev"`
}

// label names the software as the report does.
func (s VulnerableSoftware) label() string {
	l := s.Product + " " + s.Version
	switch {
	case s.Distribution != "" && len(s.Releases) > 0 && len(s.Releases) <= 2:
		l += fmt.Sprintf(" (%s %s", s.Distribution, strings.Join(s.Releases, " or "))
	case s.Distribution != "":
		l += " (" + s.Distribution
	default:
		return l
	}
	if s.Package != "" {
		l += ", package " + s.Package
	}

	return l + ")"
}

// AllVersionsSoftware is an identified product version for which NVD lists
// CVEs only for every version, with no version or range: they are not
// counted, since they say nothing about this version.
type AllVersionsSoftware struct {
	Product string   `json:"product"`
	Version string   `json:"version"`
	CVEs    []string `json:"cves"`
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
	// AllVersions are the versions with CVEs NVD lists for every version.
	AllVersions []AllVersionsSoftware `json:"all_versions,omitempty"`
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

	type key struct{ product, version, distro, family, pkg string }
	endpoints := map[key][]string{}
	var order []key
	for _, s := range services.Services {
		for _, p := range s.Identified {
			k := key{p.Product, p.Version, p.Distribution, p.Family, p.Package}
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
			k := key{p.Product, p.Version, p.Distribution, p.Family, p.Package}
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
		if status != vuln.Checked {
			// versions that differ only by distribution are listed once
			i := slices.IndexFunc(out.Unchecked, func(u UncheckedSoftware) bool {
				return u.Product == k.product && u.Version == k.version && u.Status == status
			})
			if i < 0 {
				out.Unchecked = append(out.Unchecked, UncheckedSoftware{Product: k.product, Version: k.version,
					Status: status, Reason: reason})
				i = len(out.Unchecked) - 1
			}

			out.Unchecked[i].Endpoints += len(endpoints[k])
			continue
		}

		var ranged []vuln.Match
		var unranged []string
		for _, m := range matches {
			if m.AllVersions {
				unranged = append(unranged, m.CVE)
			} else {
				ranged = append(ranged, m)
			}
		}
		if len(unranged) > 0 {
			sort.Strings(unranged)
			out.AllVersions = append(out.AllVersions, AllVersionsSoftware{Product: k.product, Version: k.version,
				CVEs: unranged})
		}

		v := VulnerableSoftware{Product: k.product, Version: k.version, Distribution: k.distro, Package: k.pkg,
			Endpoints: endpoints[k], CVEs: ranged}
		judgeByDistribution(&v, data, k.family)

		if len(v.CVEs)+len(v.Update) == 0 {
			label = v.label()
			if len(v.Settled) > 0 {
				label += fmt.Sprintf(": %d CVE(s) settled by its data", len(v.Settled))
			}

			out.Clean = append(out.Clean, label)
			continue
		}
		for _, m := range slices.Concat(v.CVEs, v.Update) {
			if m.KEV {
				v.KEV++
			}
		}

		out.Software = append(out.Software, v)
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

		fmt.Fprintf(&b, "\n%s on %s: %d CVE(s)", s.label(), where, len(s.CVEs)+len(s.Update))
		if s.KEV > 0 {
			fmt.Fprintf(&b, ", %d known exploited", s.KEV)
		}
		if s.Distro() {
			fmt.Fprintf(&b, "; by %s's data, %d still apply, %d fixed by an update, and %d more settled (not "+
				"affected, or fixed in this package)", s.Distribution, len(s.CVEs), len(s.Update), len(s.Settled))
		}

		b.WriteString("\n")
		if s.DistroNote != "" {
			fmt.Fprintf(&b, "  (%s)\n", s.DistroNote)
		}

		writeMatches(&b, s.CVEs, "  ")
		if len(s.Update) > 0 {
			article := "a"
			if strings.ContainsRune("AEIOU", rune(s.Distribution[0])) {
				article = "an"
			}

			fmt.Fprintf(&b, "  Fixed by %s %s update; these apply only if the host has not installed it:\n",
				article, s.Distribution)
			writeMatches(&b, s.Update, "    ")
		}
	}

	if len(r.Clean) > 0 {
		fmt.Fprintf(&b, "\nNo CVEs for: %s\n", strings.Join(r.Clean, ", "))
	}
	if len(r.AllVersions) > 0 {
		b.WriteString("\nNot counted: CVEs NVD lists for every version, with no version range, so they say nothing " +
			"about these versions:\n")
		for _, a := range r.AllVersions {
			fmt.Fprintf(&b, "  %s %s: %s\n", a.Product, a.Version, strings.Join(a.CVEs, ", "))
		}
	}
	if len(r.Unchecked) > 0 {
		b.WriteString("\nNot checked:\n")
		for _, u := range r.Unchecked {
			fmt.Fprintf(&b, "  %s on %d endpoint(s): %s\n", strings.TrimSpace(u.Product+" "+u.Version), u.Endpoints,
				u.Reason)
		}
	}

	b.WriteString("\nMatched by the version in stored headers, banners and asset URLs, and, where the same " +
		"header or banner names a distribution whose security data was read (Debian, Ubuntu, Red Hat), by that " +
		"distribution's own records, since it backports fixes without changing the version. Software can hide " +
		"or fake its version, so confirm with the vendor's advisory. CVE data from the NVD; known exploited " +
		"vulnerabilities from CISA's KEV catalog.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s)%s", r.Reason, partialAdvice(r.Reason))
	}

	b.WriteString("\n")
	return b.String()
}

// Distro reports whether the distribution's data judged the CVEs.
func (s VulnerableSoftware) Distro() bool {
	return s.Distribution != "" && s.DistroNote == ""
}

// writeMatches writes up to vulnerableExamples CVEs, the strongest first.
func writeMatches(b *strings.Builder, matches []vuln.Match, indent string) {
	for i, m := range matches {
		if i == vulnerableExamples {
			fmt.Fprintf(b, "%s... and %d more\n", indent, len(matches)-i)
			break
		}

		fmt.Fprintf(b, "%s%s", indent, m.CVE)
		if m.Score > 0 {
			fmt.Fprintf(b, " %.1f %s", m.Score, m.Severity)
		}
		if m.KEV {
			fmt.Fprintf(b, "; known exploited (CISA KEV since %s): %s", m.KEVAdded, m.KEVName)
		}
		if d := m.Distro; d != nil {
			switch {
			case d.Advisory != "":
				fmt.Fprintf(b, "; fixed by %s", d.Advisory)
			case d.Verdict == vuln.VerdictUpdate && d.Fixed != "":
				fmt.Fprintf(b, "; fixed in %s", d.Fixed)
			case d.Verdict == vuln.VerdictUntracked:
				b.WriteString("; not in the distribution's records")
			}
		}

		fmt.Fprintf(b, " https://nvd.nist.gov/vuln/detail/%s\n", m.CVE)
	}
}

// distroNames are the families' names for the report.
var distroNames = map[string]string{vuln.FamilyDebian: "Debian", vuln.FamilyUbuntu: "Ubuntu",
	vuln.FamilyRedHat: "Red Hat"}

// judgeByDistribution sorts a version's CVEs by its distribution's data:
// those that still apply, those a distribution update fixes, and those
// the distribution settled (not affected, or fixed in the package the
// banner names). Without a family, or without its data, they all stand,
// and the note says why.
func judgeByDistribution(v *VulnerableSoftware, data *vuln.Data, family string) {
	switch {
	case v.Distribution == "":
		return
	case family == "":
		v.DistroNote = v.Distribution + " backports fixes without changing the version, and its own errata " +
			"are not read, so these are matched by version alone"
		return
	}

	ids := make([]string, 0, len(v.CVEs))
	for _, m := range v.CVEs {
		ids = append(ids, m.CVE)
	}

	verdicts := data.Judge(v.Product, vuln.DistroServer{Family: family, Upstream: v.Version, Package: v.Package},
		ids)
	if verdicts == nil {
		v.DistroNote = fmt.Sprintf("no %s security data has been fetched for it yet: run `amass vuln-update`",
			distroNames[family])
		return
	}

	var still []vuln.Match
	for _, m := range v.CVEs {
		verdict := verdicts[m.CVE]
		m.Distro = &verdict
		if len(v.Releases) == 0 {
			v.Releases = verdict.Releases
		}

		switch verdict.Verdict {
		case vuln.VerdictNotAffected, vuln.VerdictFixed:
			v.Settled = append(v.Settled, m)
		case vuln.VerdictUpdate:
			v.Update = append(v.Update, m)
		default:
			still = append(still, m)
		}
	}

	v.CVEs = still
}

// Facts implements Report: "kev" for each known exploited CVE and "cve"
// for the others that still apply, and "update" for those a distribution
// update fixes, with the product version.
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
		for _, m := range s.Update {
			out = append(out, fmt.Sprintf("update %s %s %s", m.CVE, s.Product, s.Version))
		}
	}

	return out
}

// Partial implements Report.
func (r VulnerableReport) Partial() (bool, string) { return r.Truncated, r.Reason }
