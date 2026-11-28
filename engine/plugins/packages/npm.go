// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// npmMaxPage is the most results the npm search returns in one answer.
const npmMaxPage = 250

// npmSearch is the part of an npm registry search answer read here.
type npmSearch struct {
	Objects []struct {
		Package struct {
			Name  string `json:"name"`
			Scope string `json:"scope"`
			Date  string `json:"date"`
			Links struct {
				Homepage   string `json:"homepage"`
				Repository string `json:"repository"`
			} `json:"links"`
			Publisher struct {
				Username string `json:"username"`
				Email    string `json:"email"`
			} `json:"publisher"`
			Maintainers []struct {
				Username string `json:"username"`
				Email    string `json:"email"`
			} `json:"maintainers"`
		} `json:"package"`
	} `json:"objects"`
}

// parseNPMSearch reads the packages of a search answer that are tied to the
// footprint: a maintainer's or the publisher's address is in it, or the
// homepage is. A scoped package's namespace is its scope; an unscoped
// package's is its publishing user.
func parseNPMSearch(data []byte, f support.Footprint) ([]pkg, error) {
	var s npmSearch
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	var out []pkg
	for _, o := range s.Objects {
		n := o.Package
		if n.Name == "" {
			continue
		}

		var own []string
		domain := ""
		emails := []string{n.Publisher.Email}
		for _, m := range n.Maintainers {
			emails = append(emails, m.Email)
		}
		for _, e := range emails {
			e = strings.ToLower(strings.TrimSpace(e))
			if d := f.Address(e); d != "" && !slices.Contains(own, e) {
				own = append(own, e)
				if domain == "" {
					domain = d
				}
			}
		}
		urls, homeDomain := tiedURLs(f, pkgURL{n.Links.Homepage, RoleHomepage},
			pkgURL{n.Links.Repository, RoleRepository})
		if domain == "" {
			domain = homeDomain
		}
		if domain == "" {
			continue
		}

		name, namespace := n.Name, ""
		if n.Scope != "" && n.Scope != "unscoped" && strings.HasPrefix(n.Name, "@") {
			namespace, name, _ = strings.Cut(n.Name, "/")
		} else if n.Publisher.Username != "" {
			namespace = "~" + n.Publisher.Username
		} else {
			continue
		}

		out = append(out, pkg{registry: "npm", namespace: namespace, name: name, title: n.Name, purl: npmPurl(n.Name),
			updated: millis(n.Date), maintainers: own, domain: domain, urls: urls})
	}
	return out, nil
}

// npmPurl returns the Package URL of an npm package; a scope's "@" is
// percent-encoded, as the purl specification requires.
func npmPurl(name string) string {
	return "pkg:npm/" + strings.Replace(name, "@", "%40", 1)
}

// npm returns the npm packages a search for the domain finds that are tied to
// the footprint, newest first.
func (p *packagesPlugin) npm(e *et.Event, apex string, f support.Footprint) []pkg {
	data := p.search(e, p.catalog.NPM.Search, url.Values{"text": {apex},
		"size": {strconv.Itoa(min(p.catalog.MaxPackages, npmMaxPage))}})
	pkgs, err := parseNPMSearch(data, f)
	if err != nil {
		return nil
	}
	return newest(pkgs, p.catalog.MaxPackages)
}
