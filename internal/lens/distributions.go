// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"github.com/owasp-amass/amass/v5/internal/vuln"
)

var distributionsJSON = semantics.File("distributions.json")

type distribution struct {
	Name     string   `json:"name"`
	Family   string   `json:"family,omitempty"`
	Patterns []string `json:"patterns"`
	Source   string   `json:"source"`
	res      []*regexp.Regexp
}

type distributions struct {
	License       string         `json:"_license"`
	About         string         `json:"_about"`
	Distributions []distribution `json:"distributions"`
}

var loadDistributions = sync.OnceValue(func() distributions {
	var c distributions
	if err := graph.DecodeStrict(distributionsJSON, &c); err != nil {
		panic("distributions.json: " + err.Error())
	}

	for i, d := range c.Distributions {
		switch d.Family {
		case "", vuln.FamilyDebian, vuln.FamilyUbuntu, vuln.FamilyRedHat:
		default:
			panic(fmt.Sprintf("distributions.json: %s has unknown family %q", d.Name, d.Family))
		}
		if d.Name == "" || len(d.Patterns) == 0 || !strings.HasPrefix(d.Source, "https://") {
			panic("distributions.json: a distribution needs a name, patterns and an https source")
		}

		for _, p := range d.Patterns {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				panic(fmt.Sprintf("distributions.json: %s: %v", d.Name, err))
			}

			c.Distributions[i].res = append(c.Distributions[i].res, re)
		}
	}

	return c
})

// identifyDistribution returns the distribution a header or banner names,
// its data family, and the package revision that directly follows version
// when it gives one: in "Apache/2.4.41 (Ubuntu) PHP/7.4.3-4ubuntu2.20" the
// revision is PHP's, not Apache's.
func identifyDistribution(evidence, version string) (name, family, revision string) {
	for _, d := range loadDistributions().Distributions {
		for _, re := range d.res {
			m := re.FindStringSubmatchIndex(evidence)
			if m == nil {
				continue
			}

			name, family = d.Name, d.Family
			i := re.SubexpIndex("revision")
			if i <= 0 || m[2*i] < 0 || version == "" {
				continue
			}

			start := m[2*i]
			if v := strings.Index(evidence, version); v >= 0 {
				between := evidence[min(v+len(version), start):start]
				if v+len(version) <= start && len(between) <= len(" Ubuntu-") && !strings.Contains(between, "/") {
					return name, family, evidence[start:m[2*i+1]]
				}
			}
		}
		if name != "" {
			return name, family, ""
		}
	}

	return "", "", ""
}
