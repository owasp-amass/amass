// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

// RelationMeaning is the semantics table entry for one OAM transition.
type RelationMeaning struct {
	Attribution string
	Purpose     string
	// Vendor is false when a third_party destination is registry or
	// protocol infrastructure (an abuse desk, RDAP, WHOIS or OCSP endpoint)
	// rather than a party the source depends on.
	Vendor bool
}

// SemanticsCatalog is implemented by schema catalogs that carry the full
// relationship semantics table (see internal/ai/semantics).
type SemanticsCatalog interface {
	Meaning(source, label, relationType, destination string) (RelationMeaning, bool)
}

type MeaningFunc func(source, label, relationType, destination string) (RelationMeaning, bool)

// meaningsOf returns the semantics lookup of cat: the full table when cat
// is a SemanticsCatalog, otherwise attribution only (no purpose, every
// third party treated as a vendor). It returns nil without attribution.
func MeaningsOf(cat any) MeaningFunc {
	if s, ok := cat.(SemanticsCatalog); ok {
		return s.Meaning
	}
	if a, ok := cat.(AttributionCatalog); ok {
		return func(source, label, relationType, destination string) (RelationMeaning, bool) {
			attr, ok := a.Attribution(source, label, relationType, destination)
			return RelationMeaning{Attribution: attr, Vendor: true}, ok
		}
	}

	return nil
}

// WitnessEdge is one stored relationship that supports an answer, with
// the labels of its two assets.
type WitnessEdge struct {
	EdgeID       string `json:"edge_id"`
	Label        string `json:"label"`
	RelationType string `json:"relation_type"`
	FromID       string `json:"from_id"`
	FromType     string `json:"from_type"`
	From         string `json:"from"`
	ToID         string `json:"to_id"`
	ToType       string `json:"to_type"`
	To           string `json:"to"`
	// Detail summarizes the stored relation's own fields, such as
	// "443/tcp" for a port relation.
	Detail string `json:"detail,omitempty"`
}

// Attribution values, matching internal/ai/semantics.
const (
	AttrController  = "controller"
	AttrControls    = "controls"
	AttrSameSubject = "same_subject"
	AttrThirdParty  = "third_party"
	AttrShared      = "shared"
	// attrInfrastructure is a technical dependency such as DNS resolution.
	AttrInfrastructure = "infrastructure"
)

// AttributionCatalog is implemented by schema catalogs that know what each
// OAM relationship says about who controls an asset (see
// internal/ai/semantics/oam_relations.yaml).
type AttributionCatalog interface {
	Attribution(source, label, relationType, destination string) (string, bool)
}
