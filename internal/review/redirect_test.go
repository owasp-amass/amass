// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"path/filepath"
	"testing"
	"time"
)

// mergeApplied records that the duplicate was merged into the survivor.
func mergeApplied(t *testing.T, j *Journal, id, survivor, duplicate string) {
	t.Helper()
	if _, err := j.SubmitDuplicates([]DuplicateProposal{{ID: id, Survivor: "suny polytechnic institute", SurvivorID: survivor,
		Duplicate: "suny polytechnic institute", DuplicateID: duplicate, Score: 1, Decision: "propose"}}); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordDuplicate(DuplicateOutcome{ProposalID: id, Status: ProposalApplied, Reviewer: "jeff",
		Merge: &MergeRecord{SurvivorID: survivor, DuplicateID: duplicate}}); err != nil {
		t.Fatal(err)
	}
}

// Proposals made before a merge reach the merged record: a proposal naming
// the duplicate names the survivor, one whose two ends became one record and
// one asking for what an older proposal asks are superseded, and undoing the
// merge sends them to the restored record and makes them pending again.
func TestProposalsFollowMerges(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	own := ownershipFor("142", "5287")
	same := ownershipFor("112", "5287")
	own.CreatedAt = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	same.CreatedAt = own.CreatedAt.Add(time.Hour)
	if _, err := j.SubmitOwnership([]OwnershipProposal{own, same}); err != nil {
		t.Fatal(err)
	}
	unit := RelationProposal{ID: RelationProposalID("org_unit", "142", "org_unit", "112"), Kind: "org_unit",
		FromID: "142", From: "suny polytechnic institute", Label: "org_unit", ToID: "112", To: "suny polytechnic institute", Confidence: 60}
	if _, err := j.SubmitRelations([]RelationProposal{unit}); err != nil {
		t.Fatal(err)
	}
	mergeApplied(t, j, "dup-sunypoly", "112", "142")

	state, err := j.OwnershipState()
	if err != nil {
		t.Fatal(err)
	}
	if e := state[own.ID]; e.Status != ProposalPending || e.Proposal.OwnerID != "112" || e.Proposal.Edge.ToID != "112" {
		t.Errorf("the duplicate's proposal: %s, owner %s, edge to %s", e.Status, e.Proposal.OwnerID,
			e.Proposal.Edge.ToID)
	}
	if e := state[same.ID]; e.Status != ProposalSuperseded || e.Outcome == nil ||
		e.Outcome.Reviewer != SupersededBy("dup-sunypoly") {
		t.Errorf("the survivor's later proposal for the same asset: %s", e.Status)
	}
	proposals, status, err := j.RelationState("")
	if err != nil {
		t.Fatal(err)
	}
	if status[unit.ID] != ProposalSuperseded || proposals[unit.ID].FromID != "112" {
		t.Errorf("a relation between the two merged records: %s from %s", status[unit.ID], proposals[unit.ID].FromID)
	}

	// a later merge of the survivor carries the proposal on
	mergeApplied(t, j, "dup-sunypoly-2", "300", "112")
	if state, err = j.OwnershipState(); err != nil {
		t.Fatal(err)
	}
	if e := state[own.ID]; e.Proposal.OwnerID != "300" {
		t.Errorf("after a second merge the proposal names %s", e.Proposal.OwnerID)
	}

	// undoing the first merge restores the duplicate under a new ID
	if err := j.RecordDuplicate(DuplicateOutcome{ProposalID: "dup-sunypoly", Status: ProposalRetracted, Reviewer: "jeff",
		RestoredID: "200"}); err != nil {
		t.Fatal(err)
	}
	if state, err = j.OwnershipState(); err != nil {
		t.Fatal(err)
	}
	if e := state[own.ID]; e.Status != ProposalPending || e.Proposal.OwnerID != "200" {
		t.Errorf("after the undo the duplicate's proposal: %s, owner %s", e.Status, e.Proposal.OwnerID)
	}
	if e := state[same.ID]; e.Status != ProposalPending || e.Proposal.OwnerID != "300" {
		t.Errorf("after the undo the survivor's proposal: %s, owner %s", e.Status, e.Proposal.OwnerID)
	}
	if _, status, err = j.RelationState(""); err != nil {
		t.Fatal(err)
	}
	if status[unit.ID] != ProposalPending {
		t.Errorf("after the undo the relation is %s", status[unit.ID])
	}
}
