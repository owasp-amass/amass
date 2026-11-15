// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"sort"
	"time"
)

// Match is a CVE that NVD says affects an identified version.
type Match struct {
	CVE      string  `json:"cve"`
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
	// KEV is set when CISA's catalog lists the CVE as exploited.
	KEV       bool   `json:"kev,omitempty"`
	KEVName   string `json:"kev_name,omitempty"`
	KEVAdded  string `json:"kev_added,omitempty"`
	Published string `json:"published,omitempty"`
}

// Status says whether a product version could be checked.
type Status string

const (
	// Checked: the data covers the product; Matches lists what applies.
	Checked Status = "checked"
	// NoData: the catalog names the product but the data file has none yet.
	NoData Status = "no_data"
	// NoVersion: the version is unknown, so nothing can be compared.
	NoVersion Status = "no_version"
	// Unchecked: the catalog says the version cannot be compared.
	Unchecked Status = "unchecked"
	// Unknown: the catalog does not name the product.
	Unknown Status = "unknown"
)

// Check returns the CVEs affecting a product version, the strongest first:
// those CISA lists as exploited, then by score. The reason explains a status
// other than Checked.
func (d *Data) Check(product, version string) ([]Match, Status, string) {
	cat, err := LoadCatalog()
	if err != nil {
		return nil, Unknown, err.Error()
	}

	p, reason, ok := cat.ProductNamed(product)
	switch {
	case !ok && reason != "":
		return nil, Unchecked, reason
	case !ok:
		return nil, Unknown, "no vulnerability catalog entry"
	case version == "":
		return nil, NoVersion, "the version is not known"
	}

	var out []Match
	seen := map[string]bool{}
	fetched := false
	for _, cpe := range p.CPE {
		pd := d.Products[cpe]
		if pd == nil {
			continue
		}

		fetched = true
		for id, c := range pd.CVEs {
			if seen[id] || !covers(c.Ranges, version) {
				continue
			}

			seen[id] = true
			m := Match{CVE: id, Score: c.Score, Severity: c.Severity}
			if !c.Published.IsZero() {
				m.Published = c.Published.Format(time.DateOnly)
			}
			if k, ok := d.KEV[id]; ok {
				m.KEV, m.KEVName, m.KEVAdded = true, k.Name, k.DateAdded
			}

			out = append(out, m)
		}
	}
	if !fetched {
		return nil, NoData, "no vulnerability data has been fetched for it yet"
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}

		return a.CVE > b.CVE
	})
	return out, Checked, ""
}

func covers(ranges []Range, version string) bool {
	for _, r := range ranges {
		if r.Covers(version) {
			return true
		}
	}

	return false
}
