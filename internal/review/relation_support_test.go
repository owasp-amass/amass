// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
)

// A relationship two correlators conclude is one proposal carrying both
// correlators' evidence; once it is decided, a third correlator's
// conclusion adds nothing.
func TestOneProposalPerRelationship(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	report := func(kind string, confidence int, signal, evidence string) []RelationProposal {
		return RelationProposals(lens.RelationReport{Kind: kind, Candidates: []lens.RelationCandidate{{
			FromID: "org-parent", From: "OWASP Foundation", Label: "org_unit", ToID: "org-unit", To: "OWASP Lab",
			Confidence: confidence, Signals: []string{signal}, EvidenceIDs: []string{evidence}}}})
	}

	added, err := j.SubmitRelations(report("doc_relation", 40, "a document states it", "file-1"))
	if err != nil || len(added) != 1 {
		t.Fatalf("first proposal: %v, %v", added, err)
	}
	id := added[0].ID
	if added, err := j.SubmitRelations(report("org_unit", 70, "shared address", "file-1")); err != nil ||
		len(added) != 0 {
		t.Fatalf("a second proposal for the same relationship: %v, %v", added, err)
	}
	// submitting again records the support once
	if _, err := j.SubmitRelations(report("org_unit", 70, "shared address", "file-1")); err != nil {
		t.Fatal(err)
	}

	proposals, status, err := j.RelationState("")
	if err != nil || len(proposals) != 1 || status[id] != ProposalPending {
		t.Fatalf("proposals %+v, %v, %v", proposals, status, err)
	}
	p := proposals[id]
	if !slices.Equal(p.AlsoBy, []string{"org_unit"}) || p.Confidence != 70 ||
		!slices.Equal(p.Signals, []string{"a document states it", "shared address"}) ||
		!slices.Equal(p.EvidenceIDs, []string{"file-1"}) {
		t.Errorf("folded proposal %+v", p)
	}

	if err := j.RecordRelation(RelationOutcome{ProposalID: id, Status: ProposalRejected, Reviewer: "jeff"}); err != nil {
		t.Fatal(err)
	}
	if added, err := j.SubmitRelations(report("horizontal", 90, "something else", "file-2")); err != nil ||
		len(added) != 0 {
		t.Fatalf("a rejected relationship was proposed again: %v, %v", added, err)
	}
	proposals, _, _ = j.RelationState("")
	if p := proposals[id]; len(p.AlsoBy) != 1 || p.Confidence != 70 {
		t.Errorf("a decided proposal took more evidence: %+v", p)
	}
}
