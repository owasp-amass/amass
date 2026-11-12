// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"path/filepath"
	"testing"
)

type fakeRetractor struct{ retracted []string }

func (f *fakeRetractor) RetractOwnership(_ context.Context, id string) (bool, error) {
	f.retracted = append(f.retracted, id)
	return true, nil
}

func TestRecheckAttributions(t *testing.T) {
	g := newOrgGraph()
	g.org("colgate", "colgate university", "", "", "")
	g.g.assets["cr-a"] = Asset{ID: "cr-a", Type: "ContactRecord"}
	g.g.assets["cr-b"] = Asset{ID: "cr-b", Type: "ContactRecord"}
	g.g.assets["phone"] = Asset{ID: "phone", Type: "Phone"}
	g.link("cr-a", "phone", "phone")
	g.link("cr-b", "phone", "phone")

	witness := func(from, to string) WitnessEdge {
		return WitnessEdge{FromID: from, FromType: "ContactRecord", From: from, Label: "phone", ToID: to,
			ToType: "Phone", To: to}
	}
	proposal := func(id, cr string) OwnershipProposal {
		return OwnershipProposal{ID: id, OwnerID: "colgate", AssetID: cr, Decision: GapPropose,
			Edge: ProposedEdge{FromID: cr, FromType: "ContactRecord", Label: "organization", RelationType: "SimpleRelation",
				ToID: "colgate", ToType: "Organization"},
			Witness: []WitnessEdge{witness("cr-a", "phone"), witness(cr, "phone")}}
	}

	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	kept := proposal("own-kept", "cr-b")
	gone := proposal("own-gone", "cr-c")
	person := proposal("own-person", "cr-d")
	if _, err := j.SubmitOwnership([]OwnershipProposal{kept, gone, person}); err != nil {
		t.Fatal(err)
	}
	for id, reviewer := range map[string]string{"own-kept": AutomaticReviewer, "own-gone": AutomaticReviewer,
		"own-person": "caffix"} {
		if err := j.RecordOwnership(OwnershipOutcome{ProposalID: id, Status: ProposalApplied, Reviewer: reviewer,
			EdgeID: "edge-" + id}); err != nil {
			t.Fatal(err)
		}
	}

	r := &fakeRetractor{}
	res, err := RecheckAttributions(context.Background(), g.g, r, j)
	if err != nil {
		t.Fatal(err)
	}
	// cr-c's phone relationship does not exist; a person's approval is not
	// re-checked even though cr-d's evidence is gone too.
	if res.Checked != 2 || len(r.retracted) != 1 || r.retracted[0] != "edge-own-gone" {
		t.Fatalf("checked %d, retracted %v", res.Checked, r.retracted)
	}

	state, err := j.OwnershipState()
	if err != nil {
		t.Fatal(err)
	}
	g2 := state["own-gone"]
	if g2.Status != ProposalRetracted || g2.Outcome.Reviewer != RecheckReviewer {
		t.Fatalf("own-gone = %+v", g2)
	}
	if !redecidable(g2) {
		t.Error("a re-check retraction blocks the relationship from being written again")
	}
	if redecidable(&OwnershipEntry{Status: ProposalRetracted, Outcome: &OwnershipOutcome{Reviewer: "caffix"}}) {
		t.Error("a person's retraction can be overturned")
	}
	if _, ok := OwnershipLabel(*g2); ok {
		t.Error("a re-check retraction became a training label")
	}
}
