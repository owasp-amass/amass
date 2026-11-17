// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"slices"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
)

// TestCoverageMapMatchesOAM keeps the coverage map a true invariant: every
// OAM asset type must be classified exactly once, the map must not name a type
// OAM does not define, and every lens a type names must be a real lens (a
// registered subject lens or a declared legacy lens command). When OAM gains
// an asset type, this test fails until someone classifies its coverage.
func TestCoverageMapMatchesOAM(t *testing.T) {
	m := Coverage()

	// The lenses a "lens" entry may name: the registered subject lenses plus
	// the legacy lens commands the map declares.
	valid := map[string]bool{}
	for _, l := range SubjectLenses() {
		valid[l.Name] = true
		valid[l.Command] = true
	}
	for _, l := range m.LegacyLenses {
		valid[l] = true
	}

	classified := map[string]bool{}
	for _, c := range m.AssetTypes {
		if classified[c.Type] {
			t.Errorf("asset type %s is classified more than once", c.Type)
		}
		classified[c.Type] = true

		if !slices.Contains(oam.AssetList, oam.AssetType(c.Type)) {
			t.Errorf("coverage lists %s, which OAM does not define", c.Type)
		}
		if !validSurface(c.Surface) {
			t.Errorf("%s: unknown surface %q", c.Type, c.Surface)
		}

		switch c.Surface {
		case SurfaceLens:
			if len(c.Lenses) == 0 {
				t.Errorf("%s is surfaced by a lens but names none", c.Type)
			}
			for _, name := range c.Lenses {
				if !valid[name] {
					t.Errorf("%s names lens %q, which is neither a registered subject lens nor a declared legacy lens",
						c.Type, name)
				}
			}
		default:
			if len(c.Lenses) != 0 {
				t.Errorf("%s has surface %q but names lenses %v", c.Type, c.Surface, c.Lenses)
			}
		}
		if c.Note == "" {
			t.Errorf("%s: a coverage note is required", c.Type)
		}
	}

	// Every OAM asset type must be classified.
	for _, at := range oam.AssetList {
		if !classified[string(at)] {
			t.Errorf("OAM asset type %s has no coverage classification in oam_coverage.json", at)
		}
	}
}

// TestCoverageMapLensesExist double-checks that a type claiming a dedicated
// subject lens really resolves to one through the registry (or is a declared
// legacy command), so the map cannot drift from the registry.
func TestCoverageMapLensesExist(t *testing.T) {
	m := Coverage()
	legacy := map[string]bool{}
	for _, l := range m.LegacyLenses {
		legacy[l] = true
	}

	for _, c := range m.AssetTypes {
		if c.Surface != SurfaceLens {
			continue
		}
		for _, name := range c.Lenses {
			if legacy[name] {
				continue
			}
			if _, ok := SubjectLensNamed(name); !ok {
				t.Errorf("%s names subject lens %q, which is not registered", c.Type, name)
			}
		}
	}
}
