// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
)

// StandingRule is one way an asset the scope cannot judge takes the standing
// of an asset it hangs off: an incoming relation with one of Labels from an
// asset of one of From's types, or with Outgoing, a relation from the asset
// to one (a contact record naming its organization). Through lists the
// relations by which such an asset may itself hang off another of From's
// types, followed up to max_depth without the ones between taking standing:
// an address takes the standing of a name with an alias (CNAME) to the name
// that resolves to it (standing.json).
type StandingRule struct {
	Labels   []string `json:"labels"`
	From     []string `json:"from"`
	Outgoing bool     `json:"outgoing,omitempty"`
	Through  []string `json:"through,omitempty"`
}

// StandingRules is how the expansion policy judges the assets the scope
// cannot judge by itself.
type StandingRules struct {
	License  string                    `json:"_license"`
	About    string                    `json:"_about"`
	MaxDepth int                       `json:"max_depth"`
	Inherit  map[string][]StandingRule `json:"inherit"`
}

// Standing returns the standing rules (standing.json).
var Standing = sync.OnceValue(func() StandingRules {
	var r StandingRules
	dec := json.NewDecoder(bytes.NewReader(File("standing.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		panic("standing.json: " + err.Error())
	}
	if r.MaxDepth < 1 {
		panic("standing.json: max_depth must be at least 1")
	}
	for t, rules := range r.Inherit {
		for _, rule := range rules {
			if len(rule.Labels) == 0 || len(rule.From) == 0 {
				panic(fmt.Sprintf("standing.json: %s: every rule needs labels and from", t))
			}
		}
	}
	return r
})

// Governed reports whether reach applies to an asset type the scope cannot
// judge by itself: whether it has inheritance rules.
func (r StandingRules) Governed(atype string) bool {
	return len(r.Inherit[atype]) > 0
}
