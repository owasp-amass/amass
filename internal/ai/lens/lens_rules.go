// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"sync"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/semantics"
)

// The lens rules say how the lenses walk controlled assets.
var lensRulesJSON = semantics.File("lens.json")

type lensRules struct {
	License    string   `json:"_license"`
	About      string   `json:"_about"`
	FollowLast []string `json:"follow_last"`
}

// followLast returns the asset types the footprint walk follows after
// every other controlled asset.
var followLast = sync.OnceValue(func() map[string]bool {
	var r lensRules
	if err := graph.DecodeStrict(lensRulesJSON, &r); err != nil {
		panic("lens.json: " + err.Error())
	}

	out := map[string]bool{}
	for _, t := range r.FollowLast {
		out[t] = true
	}

	return out
})
