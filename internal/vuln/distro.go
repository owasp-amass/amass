// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// The distribution families whose security data the updater reads.
const (
	FamilyDebian = "debian"
	FamilyUbuntu = "ubuntu"
	FamilyRedHat = "redhat"
)

// The state of a CVE in one release of a distribution, as its security
// team records it.
const (
	StateNotAffected = "not_affected"
	StateFixed       = "fixed"
	StateOpen        = "open"
	StateUnknown     = "unknown"
)

// DistroData is one distribution family's records for the catalog's
// packages: its own judgment of each CVE, release by release.
type DistroData struct {
	FetchedAt time.Time                 `json:"fetched_at"`
	Packages  map[string]*DistroPackage `json:"packages"`
}

// DistroPackage is one source package of a distribution.
type DistroPackage struct {
	// Releases lists, by release, the package versions the distribution's
	// records name there (shipped or fixed), which tell which release a
	// server's version belongs to. A Red Hat module stream is written
	// "stream:2.4".
	Releases map[string][]string `json:"releases"`
	// CVEs holds the states of the CVEs in the data, by CVE ID.
	CVEs map[string][]DistroState `json:"cves"`
	// Checked is when each CVE was last read, for sources read a CVE at a
	// time, with the advisories it named then.
	Checked map[string]DistroCheck `json:"checked,omitempty"`
}

// DistroCheck is when a source read a CVE a time at a time, and what it
// named then.
type DistroCheck struct {
	At         time.Time `json:"at"`
	Advisories []string  `json:"advisories,omitempty"`
}

// DistroState is a CVE's state in one release.
type DistroState struct {
	Release  string `json:"release"`
	State    string `json:"state"`
	Fixed    string `json:"fixed,omitempty"`
	Advisory string `json:"advisory,omitempty"`
}

// addRelease records a version a release names for the package.
func (p *DistroPackage) addRelease(release, version string) {
	if release == "" || version == "" || version == "0" {
		return
	}
	if p.Releases == nil {
		p.Releases = map[string][]string{}
	}
	if !slices.Contains(p.Releases[release], version) {
		p.Releases[release] = append(p.Releases[release], version)
	}
}

// Distribution verdicts on a CVE for a server, from what is least to most
// likely to leave it exposed.
const (
	VerdictNotAffected = "not_affected"
	VerdictFixed       = "fixed"
	VerdictUpdate      = "fixed_by_update"
	VerdictUntracked   = "untracked"
	VerdictOpen        = "open"
)

var verdictRank = map[string]int{VerdictNotAffected: 0, VerdictFixed: 1, VerdictUpdate: 2, VerdictUntracked: 3,
	VerdictOpen: 4}

// DistroVerdict is a distribution's judgment of a CVE for a server: the
// releases the server's version belongs to, and the verdict that leaves it
// most exposed among them.
type DistroVerdict struct {
	Verdict  string   `json:"verdict"`
	Releases []string `json:"releases,omitempty"`
	Fixed    string   `json:"fixed,omitempty"`
	Advisory string   `json:"advisory,omitempty"`
}

// DistroServer is what a server's response says about its distribution:
// the family whose data applies, the upstream version, and the full
// package version when the banner gives one.
type DistroServer struct {
	Family   string
	Upstream string
	Package  string
}

// Judge returns the distribution's verdict on each CVE for a server
// running product, from the packages the catalog names for the family.
// It returns nil when there is no data for the family or its packages.
func (d *Data) Judge(product string, s DistroServer, cves []string) map[string]DistroVerdict {
	cat, err := LoadCatalog()
	if err != nil || d.Distros == nil || d.Distros[s.Family] == nil || s.Upstream == "" {
		return nil
	}

	p, _, ok := cat.ProductNamed(product)
	if !ok {
		return nil
	}

	var pkgs []*DistroPackage
	for _, name := range packagesFor(p.Packages[s.Family], s.Upstream) {
		if dp := d.Distros[s.Family].Packages[name]; dp != nil {
			pkgs = append(pkgs, dp)
		}
	}
	if len(pkgs) == 0 {
		return nil
	}

	out := make(map[string]DistroVerdict, len(cves))
	for _, id := range cves {
		// a package that does not track the CVE says nothing; among those
		// that do, the verdict that leaves the server most exposed counts
		var best *DistroVerdict
		for _, dp := range pkgs {
			switch v := dp.judge(s, id); {
			case best == nil:
				best = &v
			case v.Verdict == VerdictUntracked:
			case best.Verdict == VerdictUntracked || verdictRank[v.Verdict] > verdictRank[best.Verdict]:
				best = &v
			}
		}

		out[id] = *best
	}

	return out
}

// packagesFor picks, among a family's packages for a product, those whose
// name carries the version's major.minor (php8.1 for PHP 8.1.2), or all of
// them when none does.
func packagesFor(names []string, upstream string) []string {
	parts := strings.SplitN(upstream, ".", 3)
	if len(names) < 2 || len(parts) < 2 {
		return names
	}

	mm := parts[0] + "." + parts[1]
	var out []string
	for _, n := range names {
		if strings.HasSuffix(n, mm) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return names
	}

	return out
}

// releasesOf returns the releases a server's version belongs to: those
// whose records name its upstream version, or, for Red Hat, a module stream
// it is in. With none, every release with records.
func (p *DistroPackage) releasesOf(s DistroServer) []string {
	var exact, streams, all []string
	for rel, versions := range p.Releases {
		all = append(all, rel)
		for _, v := range versions {
			switch {
			case strings.HasPrefix(v, "stream:"):
				if st := strings.TrimPrefix(v, "stream:"); s.Upstream == st || strings.HasPrefix(s.Upstream, st+".") {
					streams = append(streams, rel)
				}
			case CompareVersions(upstreamOf(s.Family, v), s.Upstream) == 0:
				exact = append(exact, rel)
			}
		}
	}

	// a stream counts only when no release names the exact version, and
	// for a release that names no exact version of its own
	out := exact
	for _, rel := range streams {
		if len(exact) == 0 && !slices.Contains(out, rel) && !slices.ContainsFunc(p.Releases[rel],
			func(v string) bool { return !strings.HasPrefix(v, "stream:") }) {
			out = append(out, rel)
		}
	}
	if len(out) == 0 {
		out = all
	}

	out = slices.Compact(slices.Sorted(slices.Values(out)))
	return out
}

// judge returns the verdict on one CVE for the releases the server's
// version belongs to.
func (p *DistroPackage) judge(s DistroServer, id string) DistroVerdict {
	releases := p.releasesOf(s)
	states := p.CVEs[id]

	worst := DistroVerdict{Verdict: VerdictNotAffected, Releases: releases}
	tracked := false
	for _, rel := range releases {
		v := DistroVerdict{Verdict: VerdictUntracked}
		for _, st := range states {
			if st.Release == rel {
				tracked = true
				v = verdictOf(s, st)
				break
			}
		}
		if verdictRank[v.Verdict] > verdictRank[worst.Verdict] || (worst.Fixed == "" && v.Fixed != "" &&
			v.Verdict == worst.Verdict) {
			v.Releases = releases
			worst = v
		}
	}
	if !tracked || len(releases) == 0 {
		return DistroVerdict{Verdict: VerdictUntracked, Releases: releases}
	}

	return worst
}

// verdictOf turns a release's state of a CVE into a verdict for the server.
func verdictOf(s DistroServer, st DistroState) DistroVerdict {
	v := DistroVerdict{Fixed: st.Fixed, Advisory: st.Advisory}
	switch st.State {
	case StateNotAffected:
		v.Verdict = VerdictNotAffected
	case StateOpen:
		v.Verdict = VerdictOpen
	case StateFixed:
		switch {
		case s.Family == FamilyRedHat:
			// Red Hat's servers do not name their package release
			v.Verdict = VerdictUpdate
		case s.Package != "":
			if CompareDebian(s.Package, st.Fixed) >= 0 {
				v.Verdict = VerdictFixed
			} else {
				v.Verdict = VerdictOpen
			}
		default:
			switch c := CompareVersions(s.Upstream, upstreamOf(s.Family, st.Fixed)); {
			case c > 0:
				v.Verdict = VerdictFixed
			case c == 0:
				v.Verdict = VerdictUpdate
			default:
				v.Verdict = VerdictOpen
			}
		}
	default:
		v.Verdict = VerdictUntracked
	}

	return v
}

// upstreamOf returns the upstream version in a distribution's package
// version.
func upstreamOf(family, v string) string {
	if family == FamilyRedHat {
		if _, ver, _ := parseNVR(v); ver != "" {
			return ver
		}

		return v
	}

	return UpstreamDebian(v)
}

var nvrRE = regexp.MustCompile(`^(.+)-(?:[0-9]+:)?([^-]+)-([^-]+)$`)

// parseNVR splits a Red Hat package name-[epoch:]version-release.
func parseNVR(s string) (name, version, release string) {
	m := nvrRE.FindStringSubmatch(strings.TrimSuffix(strings.TrimSuffix(s, ".rpm"), ".src"))
	if m == nil {
		return "", "", ""
	}

	return m[1], m[2], m[3]
}

var elRE = regexp.MustCompile(`\.el([0-9]+)`)

// redHatRelease returns the RHEL major release a Red Hat package names:
// .elN in a release, or the first digits of a module stream version
// (httpd:2.4-8040020211008164252.522a0ee4 is RHEL 8), and the package or
// module name and its upstream version or stream.
func redHatRelease(pkg string) (major, name, version string) {
	if i := strings.Index(pkg, ":"); i > 0 && !strings.Contains(pkg[:i], "-") {
		// a module: name:stream-version.context
		name = pkg[:i]
		rest := pkg[i+1:]
		stream, ver, ok := strings.Cut(rest, "-")
		if !ok {
			return "", "", ""
		}

		ver, _, _ = strings.Cut(ver, ".")
		if len(ver) > 18 {
			major = ver[:len(ver)-18]
		}

		return major, name, "stream:" + stream
	}

	n, v, r := parseNVR(pkg)
	if m := elRE.FindStringSubmatch(r); m != nil {
		major = m[1]
	}

	return major, n, v
}

// sortStates orders a CVE's states by release.
func sortStates(states []DistroState) {
	sort.Slice(states, func(i, j int) bool { return states[i].Release < states[j].Release })
}
