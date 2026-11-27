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
	NPM struct {
		Search string `json:"search"`
		Source string `json:"source"`
	} `json:"npm"`
	PurlSource     string   `json:"purl_source"`
	ProductType    string   `json:"product_type"`
	MaxPackages    int      `json:"max_packages"`
	MaxPOMs        int      `json:"max_poms"`
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
	for _, u := range []string{c.Maven.Search, c.Maven.Repository, c.NPM.Search} {
		if !strings.HasPrefix(u, "https://") {
			panic("package_registries.json: maven.search, maven.repository and npm.search must be https URLs")
		}
	}
	if c.ProductType == "" || c.MaxPackages <= 0 || c.MaxPOMs < 0 {
		panic("package_registries.json: product_type, max_packages and max_poms are required")
	}
	return c
})

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
