// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var coverageMapJSON = semantics.File("oam_coverage.json")

// CoverageSurface is how an OAM asset type is made answerable.
const (
	// SurfaceLens: a dedicated lens (or lenses) reports the type.
	SurfaceLens = "lens"
	// SurfaceGeneric: collected and reachable only through the generic answer
	// kinds, with no dedicated lens yet.
	SurfaceGeneric = "generic"
	// SurfaceCollectionPending: defined in OAM but no collector populates it.
	SurfaceCollectionPending = "collection_pending"
	// SurfaceOutOfScope: intentionally unsupported for external attack surface.
	SurfaceOutOfScope = "out_of_scope"
)

// AssetCoverage is how one OAM asset type is surfaced.
type AssetCoverage struct {
	Type      string   `json:"type"`
	Surface   string   `json:"surface"`
	Collected bool     `json:"collected"`
	Lenses    []string `json:"lenses"`
	Note      string   `json:"note"`
}

// CoverageMap is the coverage classification of every OAM asset type, with
// the lens commands served outside the subject-lens registry.
type CoverageMap struct {
	License      string          `json:"_license"`
	About        string          `json:"_about"`
	LegacyLenses []string        `json:"legacy_lenses"`
	AssetTypes   []AssetCoverage `json:"asset_types"`
}

var loadCoverageMap = sync.OnceValue(func() CoverageMap {
	var m CoverageMap
	if err := graph.DecodeStrict(coverageMapJSON, &m); err != nil {
		panic("oam_coverage.json: " + err.Error())
	}
	return m
})

// Coverage returns the OAM asset-type coverage map, loaded once.
func Coverage() CoverageMap { return loadCoverageMap() }

// validSurface reports whether s is a known coverage surface.
func validSurface(s string) bool {
	switch s {
	case SurfaceLens, SurfaceGeneric, SurfaceCollectionPending, SurfaceOutOfScope:
		return true
	}
	return false
}
