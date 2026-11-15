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
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var catalogJSON = semantics.File("vulnerabilities.json")

// Product is a product the services lens identifies and its CPE names.
type Product struct {
	Product string   `json:"product"`
	CPE     []string `json:"cpe"`
	Source  string   `json:"source"`
}

// UncheckedProduct is an identified product whose version cannot be compared.
type UncheckedProduct struct {
	Product string `json:"product"`
	Reason  string `json:"reason"`
}

// Catalog says where the data comes from and which products it covers.
type Catalog struct {
	License   string             `json:"_license"`
	About     string             `json:"_about"`
	NVDAPI    string             `json:"nvd_api"`
	NVDSource string             `json:"nvd_source"`
	KEVFeed   string             `json:"kev_feed"`
	KEVSource string             `json:"kev_source"`
	Products  []Product          `json:"products"`
	Unchecked []UncheckedProduct `json:"unchecked"`
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
	for _, p := range c.Products {
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
	sum := sha256.Sum256([]byte(strings.Join(c.cpes(), "\n")))
	return hex.EncodeToString(sum[:8])
}
