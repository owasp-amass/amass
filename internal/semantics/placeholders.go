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

//go:embed placeholder_organizations.json
var placeholderOrgsJSON []byte

type placeholderOrgs struct {
	License string   `json:"_license"`
	About   string   `json:"_about"`
	Names   []string `json:"names"`
	Phrases []string `json:"phrases"`
}

var loadPlaceholderOrgs = sync.OnceValue(func() placeholderOrgs {
	var p placeholderOrgs
	dec := json.NewDecoder(bytes.NewReader(placeholderOrgsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		panic("placeholder_organizations.json: " + err.Error())
	}

	for i, n := range p.Names {
		p.Names[i] = normPlaceholder(n)
	}
	for i, ph := range p.Phrases {
		p.Phrases[i] = normPlaceholder(ph)
	}

	return p
})

func normPlaceholder(s string) string {
	s = strings.ToLower(strings.Join(strings.Fields(s), " "))
	return strings.Trim(s, " .,;:'\"()[]")
}

// IsPlaceholderOrganization reports whether name is a redaction placeholder
// or template text rather than an organization's name.
func IsPlaceholderOrganization(name string) bool {
	n := normPlaceholder(name)
	if n == "" {
		return false
	}

	p := loadPlaceholderOrgs()
	for _, v := range p.Names {
		if n == v {
			return true
		}
	}
	for _, ph := range p.Phrases {
		if ph != "" && strings.Contains(n, ph) {
			return true
		}
	}

	return false
}
