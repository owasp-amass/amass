// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

// DocumentSoftware is a product documents name as their creator or producer.
// CPE is its CPE name (cpe:2.3:part:vendor:product), the Product's unique_id.
type DocumentSoftware struct {
	CPE      string   `json:"cpe"`
	Name     string   `json:"name"`
	Vendor   string   `json:"vendor"`
	Category string   `json:"category"`
	Patterns []string `json:"patterns"`
	Source   string   `json:"source"`
	res      []*regexp.Regexp
}

type documentSoftwareRules struct {
	License  string             `json:"_license"`
	About    string             `json:"_about"`
	Products []DocumentSoftware `json:"products"`
}

var loadDocumentSoftware = sync.OnceValue(func() []DocumentSoftware {
	var r documentSoftwareRules
	dec := json.NewDecoder(bytes.NewReader(File("document_software.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		panic("document_software.json: " + err.Error())
	}
	if len(r.Products) == 0 {
		panic("document_software.json: products are required")
	}

	seen := map[string]bool{}
	for i := range r.Products {
		p := &r.Products[i]
		if !strings.HasPrefix(p.CPE, "cpe:2.3:") || strings.Count(p.CPE, ":") != 4 || seen[p.CPE] {
			panic("document_software.json: " + p.CPE + " needs a unique cpe:2.3:part:vendor:product name")
		}
		seen[p.CPE] = true
		if p.Name == "" || p.Vendor == "" || len(p.Patterns) == 0 || !strings.HasPrefix(p.Source, "https://") {
			panic("document_software.json: " + p.CPE + " needs a name, a vendor, patterns and an https source")
		}
		for _, pat := range p.Patterns {
			re, err := regexp.Compile("(?i)" + pat)
			if err != nil {
				panic("document_software.json: " + p.CPE + ": " + err.Error())
			}
			for _, n := range re.SubexpNames()[1:] {
				if n != "" && n != "version" {
					panic("document_software.json: " + p.CPE + ": the only named group is version")
				}
			}
			p.res = append(p.res, re)
		}
	}

	return r.Products
})

// DocumentSoftwareProducts returns the cataloged document software.
func DocumentSoftwareProducts() []DocumentSoftware { return loadDocumentSoftware() }

// MatchDocumentSoftware returns the product a creator or producer value names
// and the version it states, if any.
func MatchDocumentSoftware(value string) (DocumentSoftware, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return DocumentSoftware{}, "", false
	}

	for _, p := range loadDocumentSoftware() {
		for _, re := range p.res {
			m := re.FindStringSubmatch(value)
			if m == nil {
				continue
			}

			var version string
			if i := re.SubexpIndex("version"); i > 0 && i < len(m) {
				version = m[i]
			}
			return p, version, true
		}
	}
	return DocumentSoftware{}, "", false
}

// ReleaseName is the name of the product's release at version, the
// ProductRelease's key: "<name> <version>".
func (p DocumentSoftware) ReleaseName(version string) string {
	if version == "" {
		return ""
	}
	return p.Name + " " + version
}
