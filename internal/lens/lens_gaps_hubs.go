// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import "github.com/owasp-amass/amass/v5/internal/graph"

// The gap lens's hub limits count only the holders outside the footprint: a
// value is a hub when many unrelated parties share it, and a large
// organization's own copies (its URLs, mailboxes, services and certificates)
// never make its value one.

// ownedCount is how many footprint assets have one of the types.
func (g *gapSearch) ownedCount(types ...string) int {
	if g.ownedTypes == nil {
		g.ownedTypes = map[string]int{}
		for _, a := range g.owned {
			g.ownedTypes[a.Type]++
		}
	}

	n := 0
	for _, t := range types {
		n += g.ownedTypes[t]
	}
	return n
}

// searchBound is how many matches of the types an exact search reads for a
// hub limit: the limit and one more, plus the footprint's own of those
// types. At most that many of the matches are the footprint's, so a search
// cut short at the bound always has more than the limit outside it.
func (g *gapSearch) searchBound(limit int, types ...string) int {
	return limit + 1 + g.ownedCount(types...)
}

// outsideAssets returns the assets not in the footprint.
func (g *gapSearch) outsideAssets(as []graph.Asset) []graph.Asset {
	out := make([]graph.Asset, 0, len(as))
	for _, a := range as {
		if _, mine := g.owned[a.ID]; !mine {
			out = append(out, a)
		}
	}
	return out
}

// outsideSteps returns the steps whose other end is not in the footprint.
func (g *gapSearch) outsideSteps(steps []step) []step {
	out := make([]step, 0, len(steps))
	for _, s := range steps {
		if _, mine := g.owned[s.other.ID]; !mine {
			out = append(out, s)
		}
	}
	return out
}
