// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed package_registries.json
var packageRegistriesJSON []byte

// PackageRegistries are the software package registries read for an
// organization's published packages. Loaded from package_registries.json;
// see that file's _about.
type PackageRegistries struct {
	License string `json:"_license"`
	About   string `json:"_about"`
	Maven   struct {
		Search             string `json:"search"`
		Repository         string `json:"repository"`
		Source             string `json:"source"`
		VerificationSource string `json:"verification_source"`
	} `json:"maven"`
	NPM       searchRegistry `json:"npm"`
	NuGet     searchRegistry `json:"nuget"`
	Crates    searchRegistry `json:"crates"`
	RubyGems  searchRegistry `json:"rubygems"`
	Packagist struct {
		Search   string `json:"search"`
		Metadata string `json:"metadata"`
		Source   string `json:"source"`
	} `json:"packagist"`
	PurlSource     string   `json:"purl_source"`
	ProductType    string   `json:"product_type"`
	MaxPackages    int      `json:"max_packages"`
	MaxPOMs        int      `json:"max_poms"`
	MaxMetadata    int      `json:"max_metadata"`
	RegistryHosts  []string `json:"registry_hosts"`
	HostingDomains []string `json:"hosting_domains"`
}

var loadPackageRegistries = sync.OnceValue(func() PackageRegistries {
	var c PackageRegistries
	dec := json.NewDecoder(bytes.NewReader(packageRegistriesJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("package_registries.json: " + err.Error())
	}
	for _, u := range []string{c.Maven.Search, c.Maven.Repository, c.NPM.Search, c.NuGet.Search, c.Crates.Search,
		c.RubyGems.Search, c.Packagist.Search, c.Packagist.Metadata} {
		if !strings.HasPrefix(u, "https://") {
			panic("package_registries.json: every registry's search and repository must be an https URL")
		}
	}
	for _, o := range []string{c.Crates.Owners, c.RubyGems.Owners} {
		if !strings.HasPrefix(o, "https://") || !strings.Contains(o, "{name}") {
			panic("package_registries.json: crates.owners and rubygems.owners must be https URLs with {name}")
		}
	}
	if c.ProductType == "" || c.MaxPackages <= 0 || c.MaxPOMs < 0 || c.MaxMetadata < 0 {
		panic("package_registries.json: product_type, max_packages, max_poms and max_metadata are required")
	}
	return c
})

// searchRegistry is a registry read through one search endpoint.
type searchRegistry struct {
	Search string `json:"search"`
	// Owners is the URL of a package's owners list, {name} its name.
	Owners string `json:"owners,omitempty"`
	Source string `json:"source"`
}

// PackageRegistryCatalog returns the package registry catalog.
func PackageRegistryCatalog() PackageRegistries { return loadPackageRegistries() }

// RegistryHost reports whether a host is a registry's or documentation
// site, where every package has a page under the one host.
func (c PackageRegistries) RegistryHost(host string) bool { return hostUnder(host, c.RegistryHosts) }

// HostingDomain reports whether a host is under a domain that gives each
// project its own subdomain (example.github.io).
func (c PackageRegistries) HostingDomain(host string) bool { return hostUnder(host, c.HostingDomains) }

// hostUnder reports whether a host is one of domains or under one.
func hostUnder(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
