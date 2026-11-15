// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// The lens rules say how the lenses walk controlled assets.
var lensRulesJSON = semantics.File("lens.json")

type lensRules struct {
	License    string              `json:"_license"`
	About      string              `json:"_about"`
	FollowLast []string            `json:"follow_last"`
	Focus      map[string][]string `json:"focus"`
}

var loadLensRules = sync.OnceValue(func() lensRules {
	var r lensRules
	if err := graph.DecodeStrict(lensRulesJSON, &r); err != nil {
		panic("lens.json: " + err.Error())
	}

	return r
})

// followLast returns the asset types the footprint walk follows after
// every other controlled asset.
var followLast = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	for _, t := range loadLensRules().FollowLast {
		out[t] = true
	}

	return out
})

// lensFocus returns the asset types a lens reads from its footprint, or nil
// when it reads every type. Tests replace it to compare with unfocused walks.
var lensFocus = func(name string) []string {
	return loadLensRules().Focus[name]
}

// footprintFocusTypes returns the types a focused walk admits and follows:
// the targets and every type that can lead to one of them.
func footprintFocusTypes(relations []graph.RelationshipSchema, meaning graph.MeaningFunc,
	targets []string) map[string]bool {
	out := footprintExpansionTypes(relations, meaning, targets)
	for _, t := range targets {
		out[t] = true
	}

	return out
}
