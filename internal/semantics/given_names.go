// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
)

// givenNameRules are the groups of given names that are forms of one
// another, loaded from given_names.json.
type givenNameRules struct {
	License string     `json:"_license"`
	About   string     `json:"_about"`
	Groups  [][]string `json:"groups"`

	groups map[string][]int
}

var loadGivenNames = sync.OnceValue(func() *givenNameRules {
	r := &givenNameRules{}
	dec := json.NewDecoder(bytes.NewReader(File("given_names.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		panic("given_names.json: " + err.Error())
	}

	r.groups = map[string][]int{}
	for i, g := range r.Groups {
		for _, n := range g {
			n = strings.ToLower(strings.TrimSpace(n))
			r.groups[n] = append(r.groups[n], i)
		}
	}
	return r
})

// GivenNameForms reports whether two different given names are forms of one
// another (robert and bob, katherine and kate), by given_names.json. Names
// are compared lower-cased; pass them in plain letters (PlainText).
func GivenNameForms(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" || a == b {
		return false
	}

	r := loadGivenNames()
	for _, i := range r.groups[a] {
		for _, j := range r.groups[b] {
			if i == j {
				return true
			}
		}
	}
	return false
}
