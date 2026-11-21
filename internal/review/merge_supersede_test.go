// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
)

// ownershipFor proposes that org owns the contact record asset.
func ownershipFor(org, asset string) OwnershipProposal {
	edge := lens.ProposedEdge{FromID: asset, FromType: "ContactRecord", From: "https://rdap.example/" + asset,
		Label: "organization", RelationType: "SimpleRelation", ToID: org, ToType: "Organization", To: "Ithaca College"}
	return OwnershipProposal{ID: ProposalID(edge), Owner: "ithaca college", OwnerID: org, Asset: edge.From,
		AssetID: asset, AssetType: "ContactRecord", Edge: edge, Score: 0.4, Decision: lens.GapReview}
}

// Two records of one organization awaiting a merge (Ithaca College [142]
// into [112]) are each proposed as owning the same contact. The duplicate's
// proposal is skipped when the survivor already proposes the asset, and set
// aside when the survivor proposes it later; set aside is not a decision.
func TestPendingMergeKeepsTheSurvivorsOwnershipProposal(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if _, err := j.SubmitDuplicates([]DuplicateProposal{{ID: "dup-ithaca", Survivor: "ithaca college",
		SurvivorID: "112", Duplicate: "ithaca college", DuplicateID: "142", Score: 1, Decision: "propose"}}); err != nil {
		t.Fatal(err)
	}

	// The duplicate's proposal was recorded first.
	dupFirst := ownershipFor("142", "5287")
	if _, err := j.SubmitOwnership([]OwnershipProposal{dupFirst}); err != nil {
		t.Fatal(err)
	}

	merges, err := pendingMerges(j)
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.OwnershipState()
	if err != nil {
		t.Fatal(err)
	}

	// The survivor proposes the same asset: the duplicate's is set aside.
	if err := merges.supersedeDuplicates(j, "112", "5287", state); err != nil {
		t.Fatal(err)
	}
	if _, err := j.SubmitOwnership([]OwnershipProposal{ownershipFor("112", "5287")}); err != nil {
		t.Fatal(err)
	}

	state, err = j.OwnershipState()
	if err != nil {
		t.Fatal(err)
	}
	e := state[dupFirst.ID]
	if e == nil || e.Status != ProposalRetracted || e.Outcome == nil || e.Outcome.Reviewer != SupersededReviewer {
		t.Fatalf("the duplicate's proposal = %+v", e)
	}
	if !Redecidable(e) {
		t.Error("a superseded proposal must stay re-decidable, in case the merge is rejected")
	}

	// A later duplicate proposal for an asset the survivor proposes is skipped;
	// one for an asset only the duplicate reaches is not.
	if !merges.survivorProposes("142", "5287", state) {
		t.Error("the duplicate would propose an asset the survivor already proposes")
	}
	if merges.survivorProposes("142", "9999", state) {
		t.Error("an asset only the duplicate reaches was skipped")
	}
	if merges.survivorProposes("112", "5287", state) {
		t.Error("the survivor's own proposal was skipped")
	}
	if merges.survivorProposes("777", "5287", state) {
		t.Error("an organization with no pending merge was skipped")
	}
}
