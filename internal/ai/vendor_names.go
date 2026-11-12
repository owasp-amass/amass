// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// The vendor name rules say how the third-party lens names a party that
// has no stored Organization.
//
//go:embed semantics/vendor_names.json
var vendorNamesJSON []byte

type vendorNameGroup struct {
	Vendor  string `json:"vendor"`
	Pattern string `json:"pattern"`
	Source  string `json:"source"`
	re      *regexp.Regexp
}

type vendorNameRules struct {
	License      string            `json:"_license"`
	About        string            `json:"_about"`
	ReverseZones []string          `json:"reverse_zones"`
	NameGroups   []vendorNameGroup `json:"name_groups"`
}

var loadVendorNames = sync.OnceValues(func() (vendorNameRules, error) {
	var r vendorNameRules
	if err := decodeStrict(vendorNamesJSON, &r); err != nil {
		return r, fmt.Errorf("vendor_names.json: %w", err)
	}
	for i, g := range r.NameGroups {
		if g.Vendor == "" || g.Pattern == "" || !strings.HasPrefix(g.Source, "https://") {
			return r, fmt.Errorf("vendor_names.json: group %q: vendor, pattern and a documentation source are "+
				"required", g.Vendor)
		}

		re, err := regexp.Compile(g.Pattern)
		if err != nil {
			return r, fmt.Errorf("vendor_names.json: group %s: %w", g.Vendor, err)
		}
		r.NameGroups[i].re = re
	}

	return r, nil
})

func vendorNameCatalog() vendorNameRules {
	r, err := loadVendorNames()
	if err != nil {
		panic(err)
	}

	return r
}

// reverseZone reports whether a registrable domain is a reverse lookup
// zone.
func reverseZone(domain string) bool {
	for _, z := range vendorNameCatalog().ReverseZones {
		if domain == z || strings.HasSuffix(domain, "."+z) {
			return true
		}
	}

	return false
}

// vendorNameOf names the party behind a registrable domain: its name
// group's vendor, or the domain itself.
func vendorNameOf(domain string) string {
	for _, g := range vendorNameCatalog().NameGroups {
		if g.re.MatchString(domain) {
			return g.Vendor
		}
	}

	return domain
}
