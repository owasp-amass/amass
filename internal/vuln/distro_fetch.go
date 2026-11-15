// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// distroPause spaces the requests to a distribution's API.
	distroPause = time.Second
	// ubuntuPageSize is the most CVEs Ubuntu's API returns at a time.
	ubuntuPageSize = 20
	// redHatPageSize is how many CVEs a page of Red Hat's list asks for.
	redHatPageSize = 1000
	// redHatDetails bounds how many CVEs one refresh reads from Red Hat a
	// CVE at a time; the rest are read at the next refresh.
	redHatDetails = 400
	// redHatRecheck is how old a CVE read from Red Hat may be before it is
	// read again, when its advisories have not changed.
	redHatRecheck = 30 * 24 * time.Hour
)

// errNotFound is a source's answer that it has no record.
var errNotFound = errors.New("not found")

// distroGet fetches and decodes a distribution's URL, spaced to be polite
// and asking again after a transient failure.
func (u *Updater) distroGet(ctx context.Context, rawURL string, v any) error {
	pause := distroPause
	if u.Pause > 0 {
		pause = u.Pause
	}
	if wait := pause - time.Since(u.lastDistro); !u.lastDistro.IsZero() && wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}

	u.lastDistro = time.Now()

	err := u.getJSON(ctx, rawURL, false, v)
	if err != nil && strings.Contains(err.Error(), " 404 ") {
		return errNotFound
	}

	return err
}

// updateDistros reads each distribution family's judgment of the CVEs in
// the data, for the catalog's packages. A family that cannot be read keeps
// its previous data; the returned names say which.
func (u *Updater) updateDistros(ctx context.Context, cat Catalog, d *Data) []string {
	ids := map[string]bool{}
	for _, p := range d.Products {
		for id := range p.CVEs {
			ids[id] = true
		}
	}

	var failed []string
	for _, dist := range cat.Distributions {
		pkgs := cat.packages(dist.Family)
		if len(pkgs) == 0 {
			continue
		}

		var next *DistroData
		var err error
		switch dist.Family {
		case FamilyDebian:
			next, err = u.fetchDebian(ctx, dist, pkgs, ids)
		case FamilyUbuntu:
			next, err = u.fetchUbuntu(ctx, dist, pkgs, ids)
		case FamilyRedHat:
			next, err = u.fetchRedHat(ctx, dist, pkgs, ids, d.Distros[dist.Family])
		}
		if err != nil {
			if ctx.Err() != nil {
				return failed
			}

			u.logf("%s security data: not fetched: %v", dist.Name, err)
			failed = append(failed, dist.Name+" security data")
			continue
		}

		next.FetchedAt = u.now().UTC()
		d.Distros[dist.Family] = next
		u.logf("%s security data: %d package(s)", dist.Name, len(next.Packages))
	}

	return failed
}

// debianRelease is one release's record of a CVE in Debian's tracker.
type debianRelease struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories"`
	FixedVersion string            `json:"fixed_version"`
}

// fetchDebian reads Debian's security tracker, which holds every package,
// keeping only the catalog's packages and the CVEs in the data. The file
// is decoded a package at a time so the rest is never held in memory.
func (u *Updater) fetchDebian(ctx context.Context, dist Distribution, pkgs []string,
	ids map[string]bool) (*DistroData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dist.Data, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "OWASP Amass vulnerability updater")
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", req.URL.Host, resp.Status)
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<30))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("the tracker data is not a JSON object: %v", err)
	}

	out := &DistroData{Packages: map[string]*DistroPackage{}}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}

		name, _ := t.(string)
		if !slices.Contains(pkgs, name) {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}

			continue
		}

		var cves map[string]struct {
			Releases map[string]debianRelease `json:"releases"`
		}
		if err := dec.Decode(&cves); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		p := &DistroPackage{CVEs: map[string][]DistroState{}}
		for id, c := range cves {
			for rel, r := range c.Releases {
				for _, v := range r.Repositories {
					p.addRelease(rel, v)
				}
				if !ids[id] {
					continue
				}

				st := DistroState{Release: rel}
				switch {
				case r.Status == "resolved" && r.FixedVersion == "0":
					st.State = StateNotAffected
				case r.Status == "resolved":
					st.State, st.Fixed = StateFixed, r.FixedVersion
					p.addRelease(rel, r.FixedVersion)
				case r.Status == "open":
					st.State = StateOpen
				default:
					st.State = StateUnknown
				}

				p.CVEs[id] = append(p.CVEs[id], st)
			}

			sortStates(p.CVEs[id])
		}

		out.Packages[name] = p
	}

	return out, nil
}

// ubuntuPage is a page of Ubuntu's CVEs for a package.
type ubuntuPage struct {
	TotalResults int `json:"total_results"`
	CVEs         []struct {
		ID       string `json:"id"`
		Packages []struct {
			Name     string `json:"name"`
			Statuses []struct {
				Release     string `json:"release_codename"`
				Status      string `json:"status"`
				Description string `json:"description"`
			} `json:"statuses"`
		} `json:"packages"`
	} `json:"cves"`
}

var versionStart = regexp.MustCompile(`^[0-9]`)

// fetchUbuntu reads, package by package, Ubuntu's records of the CVEs in
// the data.
func (u *Updater) fetchUbuntu(ctx context.Context, dist Distribution, pkgs []string,
	ids map[string]bool) (*DistroData, error) {
	out := &DistroData{Packages: map[string]*DistroPackage{}}
	for _, name := range pkgs {
		p := &DistroPackage{CVEs: map[string][]DistroState{}}
		for offset := 0; ; {
			q := url.Values{}
			q.Set("package", name)
			q.Set("limit", strconv.Itoa(ubuntuPageSize))
			q.Set("offset", strconv.Itoa(offset))

			var page ubuntuPage
			if err := u.distroGet(ctx, dist.Data+"?"+q.Encode(), &page); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			for _, c := range page.CVEs {
				for _, pkg := range c.Packages {
					if pkg.Name != name {
						continue
					}

					for _, s := range pkg.Statuses {
						if s.Release == "" || s.Release == "upstream" || s.Status == "DNE" {
							continue
						}
						if s.Status == "released" && versionStart.MatchString(s.Description) {
							p.addRelease(s.Release, s.Description)
						}
						if !ids[c.ID] {
							continue
						}

						st := DistroState{Release: s.Release}
						switch s.Status {
						case "released":
							st.State, st.Fixed = StateFixed, s.Description
						case "not-affected":
							st.State = StateNotAffected
						case "needed", "deferred", "ignored", "pending", "active":
							st.State = StateOpen
						default:
							st.State = StateUnknown
						}

						p.CVEs[c.ID] = append(p.CVEs[c.ID], st)
					}

					sortStates(p.CVEs[c.ID])
				}
			}

			// a page may hold fewer than asked, so the next starts after it
			offset += len(page.CVEs)
			if len(page.CVEs) == 0 || offset >= page.TotalResults {
				break
			}
		}

		out.Packages[name] = p
	}

	return out, nil
}

// redHatListed is one CVE in Red Hat's list for a package.
type redHatListed struct {
	CVE              string   `json:"CVE"`
	Advisories       []string `json:"advisories"`
	AffectedPackages []string `json:"affected_packages"`
}

// redHatCVE is the part of Red Hat's record of a CVE the updater reads.
type redHatCVE struct {
	AffectedRelease []struct {
		ProductName string `json:"product_name"`
		Advisory    string `json:"advisory"`
		Package     string `json:"package"`
	} `json:"affected_release"`
	PackageState []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
	} `json:"package_state"`
}

var rhelProduct = regexp.MustCompile(`^Red Hat Enterprise Linux ([0-9]+)$`)

// redHatNames reports whether a package name in Red Hat's data, a package,
// a module, or module:stream/package, names pkg.
func redHatNames(name, pkg string) bool {
	if name == pkg {
		return true
	}
	if mod, rest, ok := strings.Cut(name, "/"); ok {
		m, _, _ := strings.Cut(mod, ":")
		return rest == pkg || m == pkg
	}

	m, _, _ := strings.Cut(name, ":")
	return m == pkg
}

// fetchRedHat reads Red Hat's list of the CVEs it tracks for each package,
// which names the packages that fix them, then reads a CVE at a time those
// it has not fixed in every release, for whether they affect it. A CVE
// read before is read again when its advisories change or it is older
// than redHatRecheck; at most redHatDetails are read in one refresh.
func (u *Updater) fetchRedHat(ctx context.Context, dist Distribution, pkgs []string, ids map[string]bool,
	prev *DistroData) (*DistroData, error) {
	out := &DistroData{Packages: map[string]*DistroPackage{}}
	budget := redHatDetails
	for _, name := range pkgs {
		var old *DistroPackage
		if prev != nil {
			old = prev.Packages[name]
		}

		var listed []redHatListed
		for page := 1; ; page++ {
			q := url.Values{}
			q.Set("package", name)
			q.Set("per_page", strconv.Itoa(redHatPageSize))
			q.Set("page", strconv.Itoa(page))

			var batch []redHatListed
			if err := u.distroGet(ctx, dist.List+"?"+q.Encode(), &batch); err != nil {
				if errors.Is(err, errNotFound) {
					break
				}

				return nil, fmt.Errorf("%s: %w", name, err)
			}

			listed = append(listed, batch...)
			if len(batch) < redHatPageSize {
				break
			}
		}

		p := &DistroPackage{CVEs: map[string][]DistroState{}, Checked: map[string]DistroCheck{}}
		var needed []redHatListed
		for _, l := range listed {
			// the fixing packages name the releases and their versions
			fixed := map[string]string{}
			for _, pkg := range l.AffectedPackages {
				if major, n, v := redHatRelease(pkg); major != "" && redHatNames(n, name) {
					p.addRelease(major, v)
					fixed[major] = pkg
				}
			}
			if !ids[l.CVE] {
				continue
			}

			for _, major := range slices.Sorted(maps.Keys(fixed)) {
				p.CVEs[l.CVE] = append(p.CVEs[l.CVE], DistroState{Release: major, State: StateFixed,
					Fixed: fixed[major]})
			}

			// a record read before stands while its advisories are the same
			if old != nil {
				if chk, ok := old.Checked[l.CVE]; ok && slices.Equal(chk.Advisories, sortedCopy(l.Advisories)) &&
					u.now().Sub(chk.At) < redHatRecheck {
					p.CVEs[l.CVE], p.Checked[l.CVE] = old.CVEs[l.CVE], chk
					continue
				}
			}

			needed = append(needed, l)
		}

		// only CVEs not fixed in every release need their record
		slices.SortFunc(needed, func(a, b redHatListed) int { return strings.Compare(b.CVE, a.CVE) })
		for _, l := range needed {
			if len(p.CVEs[l.CVE]) >= len(p.Releases) && len(p.Releases) > 0 {
				continue
			}
			if budget == 0 {
				break
			}

			budget--

			var rec redHatCVE
			if err := u.distroGet(ctx, dist.Data+l.CVE+".json", &rec); err != nil {
				if errors.Is(err, errNotFound) {
					continue
				}

				return nil, fmt.Errorf("%s %s: %w", name, l.CVE, err)
			}

			p.CVEs[l.CVE] = redHatStates(rec, name, p)
			p.Checked[l.CVE] = DistroCheck{At: u.now().UTC(), Advisories: sortedCopy(l.Advisories)}
		}

		out.Packages[name] = p
	}

	return out, nil
}

// redHatStates reads a CVE's states for a package from Red Hat's record:
// the releases an advisory fixed, then the states of the others.
func redHatStates(rec redHatCVE, pkg string, p *DistroPackage) []DistroState {
	byRelease := map[string]DistroState{}
	for _, r := range rec.AffectedRelease {
		m := rhelProduct.FindStringSubmatch(r.ProductName)
		if m == nil {
			continue
		}
		if _, n, v := redHatRelease(r.Package); redHatNames(n, pkg) {
			p.addRelease(m[1], v)
			byRelease[m[1]] = DistroState{Release: m[1], State: StateFixed, Fixed: r.Package, Advisory: r.Advisory}
		}
	}
	for _, s := range rec.PackageState {
		m := rhelProduct.FindStringSubmatch(s.ProductName)
		if m == nil || !redHatNames(s.PackageName, pkg) {
			continue
		}
		if _, ok := byRelease[m[1]]; ok {
			continue
		}

		st := DistroState{Release: m[1]}
		switch strings.ToLower(s.FixState) {
		case "not affected":
			st.State = StateNotAffected
		case "affected", "will not fix", "fix deferred", "out of support scope":
			st.State = StateOpen
		default:
			st.State = StateUnknown
		}

		byRelease[m[1]] = st
	}

	var out []DistroState
	for _, rel := range slices.Sorted(maps.Keys(byRelease)) {
		out = append(out, byRelease[rel])
	}

	return out
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}
