// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var productFingerprintsJSON = semantics.File("product_fingerprints.json")

type productFingerprint struct {
	Product      string   `json:"product"`
	Vendor       string   `json:"vendor"`
	Header       string   `json:"header,omitempty"`
	Banner       bool     `json:"banner,omitempty"`
	ServiceTypes []string `json:"service_types,omitempty"`
	Pattern      string   `json:"pattern"`
	Version      int      `json:"version"`
	Source       string   `json:"source"`
	re           *regexp.Regexp
}

type productFingerprints struct {
	License      string               `json:"_license"`
	About        string               `json:"_about"`
	Fingerprints []productFingerprint `json:"fingerprints"`
}

func (c productFingerprints) validate() error {
	for i, f := range c.Fingerprints {
		switch {
		case f.Product == "" || !strings.HasPrefix(f.Source, "https://"):
			return fmt.Errorf("fingerprint %d: product and a documentation source are required", i)
		case (f.Header == "") == !f.Banner:
			return fmt.Errorf("fingerprint %s: set exactly one of header or banner", f.Product)
		case f.Banner && len(f.ServiceTypes) == 0:
			return fmt.Errorf("fingerprint %s: a banner fingerprint names its service_types", f.Product)
		}

		re, err := regexp.Compile("(?i)" + f.Pattern)
		if err != nil {
			return fmt.Errorf("fingerprint %s: %w", f.Product, err)
		}
		if f.Version < 0 || f.Version > re.NumSubexp() {
			return fmt.Errorf("fingerprint %s: version group %d is not in the pattern", f.Product, f.Version)
		}

		c.Fingerprints[i].re = re
		c.Fingerprints[i].Header = strings.ToLower(f.Header)
	}

	return nil
}

var loadProductFingerprints = sync.OnceValue(func() productFingerprints {
	var c productFingerprints
	if err := graph.DecodeStrict(productFingerprintsJSON, &c); err != nil {
		panic("product_fingerprints.json: " + err.Error())
	}
	if err := c.validate(); err != nil {
		panic("product_fingerprints.json: " + err.Error())
	}

	return c
})

// IdentifiedProduct is software a service's stored response names, by a
// fingerprint. It is computed, not stored.
type IdentifiedProduct struct {
	Product string `json:"product"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
	// Evidence is the stored header or banner the fingerprint matched;
	// Source is the documentation the fingerprint cites.
	Evidence string `json:"evidence"`
	Source   string `json:"source"`
	// Distribution is the Linux distribution the same header or banner
	// names, whose data Family applies, and Package the distribution's
	// package version when the banner gives its revision.
	Distribution string `json:"distribution,omitempty"`
	Family       string `json:"distribution_family,omitempty"`
	Package      string `json:"package,omitempty"`
}

// Label names the product, its version and distribution.
func (p IdentifiedProduct) Label() string {
	l := strings.TrimSpace(p.Product + " " + p.Version)
	switch {
	case p.Package != "" && p.Distribution != "":
		l += " (" + p.Distribution + " package " + p.Package + ")"
	case p.Distribution != "":
		l += " (" + p.Distribution + ")"
	}

	return l
}

// identifyProducts matches a service's stored response headers and banner
// against the fingerprint catalog.
func identifyProducts(svc graph.Asset) []IdentifiedProduct {
	data, err := json.Marshal(svc.Content)
	if err != nil {
		return nil
	}

	var f struct {
		Type       string              `json:"service_type"`
		Output     string              `json:"output"`
		Attributes map[string][]string `json:"attributes"`
	}
	if json.Unmarshal(data, &f) != nil {
		return nil
	}

	headers := map[string][]string{}
	for k, v := range f.Attributes {
		headers[strings.ToLower(k)] = append(headers[strings.ToLower(k)], v...)
	}

	banner := strings.TrimSpace(strings.SplitN(f.Output, "\n", 2)[0])

	var out []IdentifiedProduct
	seen := map[string]bool{}
	add := func(fp productFingerprint, value string) {
		m := fp.re.FindStringSubmatch(value)
		if m == nil {
			return
		}

		p := IdentifiedProduct{Product: fp.Product, Vendor: fp.Vendor, Evidence: value, Source: fp.Source}
		if fp.Version > 0 {
			p.Version = m[fp.Version]
		}
		// a distribution counts only when the same header or banner names it
		if name, family, rev := identifyDistribution(value, p.Version); name != "" {
			p.Distribution, p.Family = name, family
			if rev != "" && p.Version != "" {
				p.Package = p.Version + "-" + rev
			}
		}

		key := p.Product + "|" + p.Version
		if seen[key] {
			return
		}
		// A versioned match replaces an unversioned one of the same product.
		for i, o := range out {
			if o.Product == p.Product && o.Version == "" && p.Version != "" {
				out = slices.Delete(out, i, i+1)
				break
			}
			if o.Product == p.Product && p.Version == "" {
				return
			}
		}

		seen[key] = true
		out = append(out, p)
	}

	for _, fp := range loadProductFingerprints().Fingerprints {
		switch {
		case fp.Header != "":
			for _, v := range headers[fp.Header] {
				add(fp, strings.TrimSpace(v))
			}
		case fp.Banner && banner != "" && slices.Contains(fp.ServiceTypes, f.Type):
			add(fp, banner)
		}
	}

	return out
}
