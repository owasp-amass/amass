// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// mavenGroup returns the Maven groupId a domain is published under: its labels
// reversed (example.com is com.example).
func mavenGroup(apex string) string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(apex), "."), ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".")
}

// mavenSearch is the part of a Maven Central search answer read here.
type mavenSearch struct {
	Response struct {
		Docs []struct {
			Group     string `json:"g"`
			Artifact  string `json:"a"`
			Latest    string `json:"latestVersion"`
			Timestamp int64  `json:"timestamp"`
		} `json:"docs"`
	} `json:"response"`
}

// parseMavenSearch reads the artifacts of a search answer that are in the
// domain's group or a group under it.
func parseMavenSearch(data []byte, group string) ([]pkg, error) {
	var s mavenSearch
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	var out []pkg
	for _, d := range s.Response.Docs {
		if d.Artifact == "" || (d.Group != group && !strings.HasPrefix(d.Group, group+".")) {
			continue
		}
		out = append(out, pkg{registry: "maven", namespace: d.Group, name: d.Artifact, title: d.Group + ":" + d.Artifact,
			purl: "pkg:maven/" + d.Group + "/" + d.Artifact, version: d.Latest, updated: d.Timestamp,
			nameTied: true})
	}
	return out, nil
}

// pom is the part of a Maven POM read here.
type pom struct {
	URL          string `xml:"url"`
	Organization struct {
		Name string `xml:"name"`
		URL  string `xml:"url"`
	} `xml:"organization"`
	SCM struct {
		URL string `xml:"url"`
	} `xml:"scm"`
}

// parsePOM returns the URLs a POM names, with their roles, and the name of
// the organization it names.
func parsePOM(data []byte) ([]pkgURL, string) {
	var p pom
	if xml.Unmarshal(data, &p) != nil {
		return nil, ""
	}

	var urls []pkgURL
	for _, u := range []pkgURL{{strings.TrimSpace(p.URL), RoleProject},
		{strings.TrimSpace(p.Organization.URL), RoleOrganization}, {strings.TrimSpace(p.SCM.URL), RoleRepository}} {
		// a POM inherited from its parent can hold ${...} placeholders
		if u.raw != "" && !strings.Contains(u.raw, "${") {
			urls = append(urls, u)
		}
	}
	return urls, strings.TrimSpace(p.Organization.Name)
}

// maven returns the domain's Maven Central packages: the artifacts in its
// group and the groups under it, newest first, with the URLs and
// organization their newest POMs name.
func (p *packagesPlugin) maven(e *et.Event, apex string) []pkg {
	group := mavenGroup(apex)
	var pkgs []pkg
	seen := map[string]bool{}
	for _, q := range []string{"g:" + group, "g:" + group + ".*"} {
		u := fmt.Sprintf("%s?%s", p.catalog.Maven.Search, url.Values{"q": {q},
			"rows": {strconv.Itoa(p.catalog.MaxPackages)}, "wt": {"json"}}.Encode())
		data, err := support.FetchBody(e, u, p.rlimit, maxPackageBody)
		if err != nil {
			continue
		}
		found, err := parseMavenSearch(data, group)
		if err != nil {
			continue
		}
		for _, k := range found {
			if !seen[k.purl] {
				seen[k.purl] = true
				pkgs = append(pkgs, k)
			}
		}
	}
	pkgs = newest(pkgs, p.catalog.MaxPackages)

	for i := range pkgs {
		version := pkgs[i].version
		if i >= p.catalog.MaxPOMs || version == "" {
			continue
		}
		u := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", strings.TrimSuffix(p.catalog.Maven.Repository, "/"),
			strings.ReplaceAll(pkgs[i].namespace, ".", "/"), pkgs[i].name, version, pkgs[i].name, version)
		if data, err := support.FetchBody(e, u, p.rlimit, maxPackageBody); err == nil {
			pkgs[i].urls, pkgs[i].organization = parsePOM(data)
		}
	}
	return pkgs
}
