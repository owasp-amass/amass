// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package vuln keeps a local copy of the vulnerability data for the
// products the services lens identifies (from the NVD CVE API and CISA's
// Known Exploited Vulnerabilities catalog), and checks an identified
// product's version against it. It reads and writes only its data file.
package vuln

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var catalogJSON = semantics.File("vulnerabilities.json")

// Product is a product the services lens identifies and its CPE names,
// and the source packages that ship it in each distribution family.
type Product struct {
	Product  string              `json:"product"`
	CPE      []string            `json:"cpe"`
	Source   string              `json:"source"`
	Packages map[string][]string `json:"packages,omitempty"`
}

// Distribution is a distribution family whose security team's data the
// updater reads: where, and the documentation of it.
type Distribution struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	// Data is the URL read: the whole tracker (Debian), or the API asked a
	// package (Ubuntu) or a CVE (Red Hat) at a time.
	Data string `json:"data"`
	// List is Red Hat's list of the CVEs it tracks for a package.
	List   string `json:"list,omitempty"`
	Source string `json:"source"`
	// Packages shows where a package name is seen in the distribution's
	// data, with {package} for the name.
	Packages string `json:"packages"`
}

// UncheckedProduct is an identified product whose version cannot be compared.
type UncheckedProduct struct {
	Product string `json:"product"`
	Reason  string `json:"reason"`
}

// Catalog says where the data comes from and which products it covers.
type Catalog struct {
	License   string `json:"_license"`
	About     string `json:"_about"`
	NVDAPI    string `json:"nvd_api"`
	NVDSource string `json:"nvd_source"`
	KEVFeed   string `json:"kev_feed"`
	KEVSource string `json:"kev_source"`
	// Distributions are the families whose own CVE data is read.
	Distributions []Distribution     `json:"distributions"`
	Products      []Product          `json:"products"`
	Unchecked     []UncheckedProduct `json:"unchecked"`
}

// LoadCatalog returns the vulnerability catalog.
var LoadCatalog = sync.OnceValues(func() (Catalog, error) {
	var c Catalog
	if err := graph.DecodeStrict(catalogJSON, &c); err != nil {
		return c, fmt.Errorf("vulnerabilities.json: %w", err)
	}
	if !strings.HasPrefix(c.NVDAPI, "https://") || !strings.HasPrefix(c.KEVFeed, "https://") {
		return c, fmt.Errorf("vulnerabilities.json: nvd_api and kev_feed must be https URLs")
	}

	families := map[string]bool{}
	for _, d := range c.Distributions {
		switch {
		case d.Family != FamilyDebian && d.Family != FamilyUbuntu && d.Family != FamilyRedHat:
			return c, fmt.Errorf("vulnerabilities.json: unknown distribution family %q", d.Family)
		case !strings.HasPrefix(d.Data, "https://") || !strings.HasPrefix(d.Source, "https://") ||
			!strings.HasPrefix(d.Packages, "https://") || !strings.Contains(d.Packages, "{package}"):
			return c, fmt.Errorf("vulnerabilities.json: distribution %s needs https data, source and packages",
				d.Family)
		case d.Family == FamilyRedHat && !strings.HasPrefix(d.List, "https://"):
			return c, fmt.Errorf("vulnerabilities.json: distribution %s needs its https list", d.Family)
		}

		families[d.Family] = true
	}
	for _, p := range c.Products {
		for fam, names := range p.Packages {
			if !families[fam] || len(names) == 0 || slices.Contains(names, "") {
				return c, fmt.Errorf("vulnerabilities.json: product %s: packages of %q name no distribution or "+
					"no package", p.Product, fam)
			}
		}
		if p.Product == "" || len(p.CPE) == 0 || !strings.HasPrefix(p.Source, "https://") {
			return c, fmt.Errorf("vulnerabilities.json: product %q: product, cpe and a source are required",
				p.Product)
		}
		for _, cpe := range p.CPE {
			if parts := strings.Split(cpe, ":"); len(parts) != 5 || parts[0] != "cpe" || parts[1] != "2.3" {
				return c, fmt.Errorf("vulnerabilities.json: product %s: %q is not cpe:2.3:part:vendor:product",
					p.Product, cpe)
			}
		}
	}

	return c, nil
})

// ProductNamed returns the catalog entry of an identified product, and
// whether the product is listed as unchecked instead (with the reason).
func (c Catalog) ProductNamed(name string) (Product, string, bool) {
	for _, p := range c.Products {
		if strings.EqualFold(p.Product, name) {
			return p, "", true
		}
	}
	for _, u := range c.Unchecked {
		if strings.EqualFold(u.Product, name) {
			return Product{}, u.Reason, false
		}
	}

	return Product{}, "", false
}

// Distribution returns the catalog entry of a distribution family.
func (c Catalog) Distribution(family string) (Distribution, bool) {
	for _, d := range c.Distributions {
		if d.Family == family {
			return d, true
		}
	}

	return Distribution{}, false
}

// packages lists, for a family, every package the catalog's products name.
func (c Catalog) packages(family string) []string {
	var out []string
	for _, p := range c.Products {
		for _, n := range p.Packages[family] {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}

	return out
}

// cpes lists every CPE name in the catalog, in order.
func (c Catalog) cpes() []string {
	var out []string
	for _, p := range c.Products {
		out = append(out, p.CPE...)
	}

	return out
}

// hash identifies the catalog's products, so the data file can tell when
// products were added.
func (c Catalog) hash() string {
	names := c.cpes()
	for _, d := range c.Distributions {
		for _, p := range c.packages(d.Family) {
			names = append(names, d.Family+":"+p)
		}
	}

	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return hex.EncodeToString(sum[:8])
}
