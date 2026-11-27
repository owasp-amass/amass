// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"slices"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
)

// Every subject and object type is an OAM asset type, and a predicate mapped
// onto an OAM relation is a valid relationship for every pair of its types.
func TestStatementPredicatesMatchOAM(t *testing.T) {
	s := StatementPredicateRules()
	for _, p := range s.Predicates {
		for _, typ := range append(slices.Clone(p.SubjectTypes), p.ObjectTypes...) {
			if !slices.Contains(oam.AssetList, oam.AssetType(typ)) {
				t.Errorf("%s names %q, not an OAM asset type", p.Name, typ)
			}
		}
		if p.OAM == nil {
			continue
		}
		for _, sub := range p.SubjectTypes {
			for _, obj := range p.ObjectTypes {
				from, to := sub, obj
				if p.OAM.Direction == "inverse" {
					from, to = obj, sub
				}
				if !oam.ValidRelationship(oam.AssetType(from), p.OAM.Label, oam.SimpleRelation, oam.AssetType(to)) {
					t.Errorf("%s: %s --%s--> %s is not an OAM relationship", p.Name, from, p.OAM.Label, to)
				}
			}
		}
	}
	if _, ok := s.Predicate("unit_of"); !ok || !s.IsCategory("staff_directory") || s.IsCategory("nonsense") {
		t.Error("lookups")
	}
	if p, _ := s.Predicate("holds_role"); !slices.Contains(s.Families(p), "people") {
		t.Errorf("holds_role families %v", s.Families(p))
	}
}
