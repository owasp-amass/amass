// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// The registries searched by text for the domain, whose packages count
// only when a URL or address they name is in the footprint: NuGet,
// crates.io, RubyGems and Packagist (package_registries.json).

// stringList reads a JSON value that is a string or a list of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*l = stringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

// millis returns an RFC 3339 time in milliseconds since the epoch, or 0.
func millis(s string) int64 {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli()
	}
	return 0
}

// search fetches a registry's search answer for the domain.
func (p *packagesPlugin) search(e *et.Event, base string, query url.Values) []byte {
	data, err := support.FetchBody(e, base+"?"+query.Encode(), p.rlimit, maxPackageBody)
	if err != nil {
		return nil
	}
	return data
}

// parseNuGetSearch reads the packages of a NuGet search answer whose project
// URL is in the footprint. A package's namespace is its first owner.
func parseNuGetSearch(data []byte, f support.Footprint) []pkg {
	var s struct {
		Data []struct {
			ID         string     `json:"id"`
			ProjectURL string     `json:"projectUrl"`
			Owners     stringList `json:"owners"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &s) != nil {
		return nil
	}

	var out []pkg
	for _, d := range s.Data {
		urls, domain := tiedURLs(f, pkgURL{d.ProjectURL, RoleProject})
		if d.ID == "" || domain == "" {
			continue
		}
		k := pkg{registry: "nuget", name: d.ID, title: d.ID, purl: "pkg:nuget/" + d.ID, urls: urls, domain: domain}
		if len(d.Owners) > 0 && strings.TrimSpace(d.Owners[0]) != "" {
			k.namespace = "~" + strings.TrimSpace(d.Owners[0])
		}
		out = append(out, k)
	}
	return out
}

// nuget returns the NuGet packages a search for the domain finds that are
// tied to the footprint.
func (p *packagesPlugin) nuget(e *et.Event, apex string, f support.Footprint) []pkg {
	data := p.search(e, p.catalog.NuGet.Search, url.Values{"q": {apex}, "take": {strconv.Itoa(p.catalog.MaxPackages)}})
	return newest(parseNuGetSearch(data, f), p.catalog.MaxPackages)
}

// parseCratesSearch reads the crates of a crates.io search answer whose
// homepage or documentation is in the footprint. A crate's namespace is its
// first owner (crateOwner).
func parseCratesSearch(data []byte, f support.Footprint) []pkg {
	var s struct {
		Crates []struct {
			Name          string `json:"name"`
			Homepage      string `json:"homepage"`
			Documentation string `json:"documentation"`
			Repository    string `json:"repository"`
			UpdatedAt     string `json:"updated_at"`
		} `json:"crates"`
	}
	if json.Unmarshal(data, &s) != nil {
		return nil
	}

	var out []pkg
	for _, c := range s.Crates {
		urls, domain := tiedURLs(f, pkgURL{c.Homepage, RoleHomepage}, pkgURL{c.Documentation, RoleProject})
		if c.Name == "" || domain == "" {
			continue
		}
		if strings.TrimSpace(c.Repository) != "" {
			urls = append(urls, pkgURL{c.Repository, RoleRepository})
		}
		out = append(out, pkg{registry: "cargo", name: c.Name, title: c.Name, purl: "pkg:cargo/" + c.Name,
			updated: millis(c.UpdatedAt), urls: urls, domain: domain})
	}
	return out
}

// crates returns the crates a crates.io search for the domain finds that are
// tied to the footprint, newest first, with their owners.
func (p *packagesPlugin) crates(e *et.Event, apex string, f support.Footprint) []pkg {
	data := p.search(e, p.catalog.Crates.Search, url.Values{"q": {apex},
		"per_page": {strconv.Itoa(min(p.catalog.MaxPackages, 100))}})
	return p.withOwners(e, newest(parseCratesSearch(data, f), p.catalog.MaxPackages), p.catalog.Crates.Owners,
		crateOwner)
}

// crateOwner returns the login of the first owner a crates.io owners answer
// lists, or "".
func crateOwner(data []byte) string {
	var o struct {
		Users []struct {
			Login string `json:"login"`
		} `json:"users"`
	}
	if json.Unmarshal(data, &o) != nil || len(o.Users) == 0 {
		return ""
	}
	return strings.TrimSpace(o.Users[0].Login)
}

// gemOwner returns the handle of the first owner a RubyGems owners answer
// lists, or "".
func gemOwner(data []byte) string {
	var o []struct {
		Handle string `json:"handle"`
	}
	if json.Unmarshal(data, &o) != nil || len(o) == 0 {
		return ""
	}
	return strings.TrimSpace(o[0].Handle)
}

// withOwners sets the namespace of at most max_metadata packages to their
// first owner, read from the owners list at tmpl ({name} the package's name)
// by owner.
func (p *packagesPlugin) withOwners(e *et.Event, pkgs []pkg, tmpl string, owner func([]byte) string) []pkg {
	for i := range pkgs {
		if i >= p.catalog.MaxMetadata {
			break
		}
		u := strings.ReplaceAll(tmpl, "{name}", url.PathEscape(pkgs[i].name))
		if data, err := support.FetchBody(e, u, p.rlimit, maxPackageBody); err == nil {
			if login := owner(data); login != "" {
				pkgs[i].namespace = "~" + login
			}
		}
	}
	return pkgs
}

// parseRubyGemsSearch reads the gems of a RubyGems search answer whose
// homepage or documentation is in the footprint. A gem's namespace is its
// first owner (gemOwner).
func parseRubyGemsSearch(data []byte, f support.Footprint) []pkg {
	var gems []struct {
		Name          string `json:"name"`
		Homepage      string `json:"homepage_uri"`
		Documentation string `json:"documentation_uri"`
		SourceCode    string `json:"source_code_uri"`
	}
	if json.Unmarshal(data, &gems) != nil {
		return nil
	}

	var out []pkg
	for _, g := range gems {
		urls, domain := tiedURLs(f, pkgURL{g.Homepage, RoleHomepage}, pkgURL{g.Documentation, RoleProject})
		if g.Name == "" || domain == "" {
			continue
		}
		if strings.TrimSpace(g.SourceCode) != "" {
			urls = append(urls, pkgURL{g.SourceCode, RoleRepository})
		}
		out = append(out, pkg{registry: "gem", name: g.Name, title: g.Name, purl: "pkg:gem/" + g.Name, urls: urls,
			domain: domain})
	}
	return out
}

// rubygems returns the gems a RubyGems search for the domain finds that are
// tied to the footprint, with their owners.
func (p *packagesPlugin) rubygems(e *et.Event, apex string, f support.Footprint) []pkg {
	data := p.search(e, p.catalog.RubyGems.Search, url.Values{"query": {apex}})
	return p.withOwners(e, newest(parseRubyGemsSearch(data, f), p.catalog.MaxPackages), p.catalog.RubyGems.Owners,
		gemOwner)
}

// parsePackagistSearch returns the package names of a Packagist search
// answer.
func parsePackagistSearch(data []byte) []string {
	var s struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	var out []string
	for _, r := range s.Results {
		if strings.Count(r.Name, "/") == 1 {
			out = append(out, r.Name)
		}
	}
	return out
}

// parsePackagistMetadata reads a package's Packagist metadata: it is kept
// when its homepage, an author's homepage or an author's address is in the
// footprint. Its namespace is its vendor.
func parsePackagistMetadata(data []byte, name string, f support.Footprint) (pkg, bool) {
	var m struct {
		Packages map[string][]struct {
			Homepage string `json:"homepage"`
			Time     string `json:"time"`
			Source   struct {
				URL string `json:"url"`
			} `json:"source"`
			Authors []struct {
				Email    string `json:"email"`
				Homepage string `json:"homepage"`
			} `json:"authors"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &m) != nil || len(m.Packages[name]) == 0 {
		return pkg{}, false
	}

	v := m.Packages[name][0] // the newest version first
	vendor, _, _ := strings.Cut(name, "/")
	k := pkg{registry: "composer", namespace: vendor, name: name, title: name, purl: "pkg:composer/" + name,
		updated: millis(v.Time)}
	links := []pkgURL{{v.Homepage, RoleHomepage}}
	for _, a := range v.Authors {
		links = append(links, pkgURL{a.Homepage, RoleOrganization})
		if d := f.Address(a.Email); d != "" {
			k.maintainers = append(k.maintainers, strings.ToLower(strings.TrimSpace(a.Email)))
			if k.domain == "" {
				k.domain = d
			}
		}
	}
	urls, domain := tiedURLs(f, links...)
	if k.domain == "" {
		k.domain = domain
	}
	if k.domain == "" {
		return pkg{}, false
	}
	k.urls = urls
	if strings.TrimSpace(v.Source.URL) != "" {
		k.urls = append(k.urls, pkgURL{v.Source.URL, RoleRepository})
	}
	return k, true
}

// packagist returns the Packagist packages a search for the domain finds
// that are tied to the footprint, reading at most max_metadata packages'
// metadata, newest first.
func (p *packagesPlugin) packagist(e *et.Event, apex string, f support.Footprint) []pkg {
	names := parsePackagistSearch(p.search(e, p.catalog.Packagist.Search, url.Values{"q": {apex},
		"per_page": {strconv.Itoa(min(p.catalog.MaxPackages, 100))}}))

	var out []pkg
	for i, name := range names {
		if i >= p.catalog.MaxMetadata {
			break
		}
		data, err := support.FetchBody(e, fmt.Sprintf("%s%s.json", p.catalog.Packagist.Metadata, name), p.rlimit,
			maxPackageBody)
		if err != nil {
			continue
		}
		if k, ok := parsePackagistMetadata(data, name, f); ok {
			out = append(out, k)
		}
	}
	return newest(out, p.catalog.MaxPackages)
}
