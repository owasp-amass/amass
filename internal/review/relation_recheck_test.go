// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func sampleReport2() lens.RelationReport {
	return lens.RelationReport{
		Kind: "org_unit",
		Candidates: []lens.RelationCandidate{{
			FromID: "org-a", From: "A", Label: "org_unit", ToID: "org-b", To: "B", Confidence: 60,
			Signals: []string{"x"},
			Witness: []graph.WitnessEdge{{EdgeID: "e2", Label: "location", FromID: "org-a", ToID: "loc-2"}},
		}},
	}
}

func gone(_ []graph.WitnessEdge) (string, error)    { return "loc-1 --location--> gone", nil }
func present(_ []graph.WitnessEdge) (string, error) { return "", nil }

func applyProposal(t *testing.T, ctx context.Context, j *Journal, s *fakeRelationStore, p RelationProposal,
	reviewer string) string {
	t.Helper()
	if _, err := j.SubmitRelations([]RelationProposal{p}); err != nil {
		t.Fatal(err)
	}
	edge, err := ApplyRelation(ctx, s, j, p, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	return edge
}

func TestRecheckRetractsAIWrite(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	s := newFakeRelationStore("org-parent", "org-unit")
	p := RelationProposals(sampleReport())[0]
	edge := applyProposal(t, ctx, j, s, p, AutomaticReviewer)

	res, err := recheckRelations(ctx, s, j, "org_unit", gone)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 1 || len(res.Retracted) != 1 || len(res.Flagged) != 0 {
		t.Fatalf("recheck result: %+v", res)
	}
	if s.hasEdge(edge) {
		t.Error("an AI-applied write whose witness is gone should be retracted (edge deleted)")
	}
	_, status, _ := j.relationRecords("org_unit")
	if status[p.ID] != ProposalRetracted {
		t.Errorf("status = %q, want retracted", status[p.ID])
	}
	if !RelationRedecidable(ProposalRetracted, RecheckReviewer) {
		t.Error("a re-check retraction must remain redecidable")
	}
}

func TestRecheckFlagsHumanWrite(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	s := newFakeRelationStore("org-a", "org-b")
	p := RelationProposals(sampleReport2())[0]
	edge := applyProposal(t, ctx, j, s, p, "jeff")

	res, err := recheckRelations(ctx, s, j, "org_unit", gone)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flagged) != 1 || len(res.Retracted) != 0 {
		t.Fatalf("a human-approved write should be flagged, not retracted: %+v", res)
	}
	if !s.hasEdge(edge) {
		t.Error("a human-approved write must not be deleted by a re-check")
	}
	flags, err := j.RelationFlags("org_unit")
	if err != nil || flags[p.ID] == "" {
		t.Errorf("proposal was not flagged for re-review: %v / %v", flags, err)
	}
	_, status, _ := j.relationRecords("")
	if status[p.ID] != ProposalApplied {
		t.Errorf("a flagged human write stays applied; status = %q", status[p.ID])
	}
}

func TestRecheckNoChangeWhenWitnessPresent(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	s := newFakeRelationStore("org-parent", "org-unit")
	p := RelationProposals(sampleReport())[0]
	edge := applyProposal(t, ctx, j, s, p, AutomaticReviewer)

	res, err := recheckRelations(ctx, s, j, "org_unit", present)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 1 || len(res.Retracted) != 0 || len(res.Flagged) != 0 {
		t.Fatalf("nothing should change when the witness is present: %+v", res)
	}
	if !s.hasEdge(edge) {
		t.Error("the edge should remain")
	}
}

func TestRelationRedecidable(t *testing.T) {
	cases := []struct {
		status, reviewer string
		want             bool
	}{
		{ProposalPending, "", true},
		{ProposalRetracted, RecheckReviewer, true},
		{ProposalRetracted, "jeff", false},
		{ProposalRejected, "jeff", false},
		{ProposalApplied, "jeff", false},
	}
	for _, c := range cases {
		if got := RelationRedecidable(c.status, c.reviewer); got != c.want {
			t.Errorf("RelationRedecidable(%q,%q) = %v, want %v", c.status, c.reviewer, got, c.want)
		}
	}
}
