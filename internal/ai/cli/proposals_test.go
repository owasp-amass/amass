// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

type fakeOwnershipWriter struct {
	writes     []ai.ProposedEdge
	confidence int
}

func (f *fakeOwnershipWriter) ApplyOwnership(_ context.Context, e ai.ProposedEdge, confidence int) (string, bool, error) {
	f.writes = append(f.writes, e)
	f.confidence = confidence
	return "77", false, nil
}

func journalWithProposal(t *testing.T) (string, ai.OwnershipProposal) {
	t.Helper()

	edge := ai.ProposedEdge{FromID: "1", FromType: "ContactRecord", From: "https://rdap.example/alumni",
		Label: "organization", RelationType: "SimpleRelation", ToID: "2", ToType: "Organization",
		To: "Synthetic University"}
	p := ai.OwnershipProposal{ID: ai.ProposalID(edge), Owner: "Synthetic University", OwnerID: "2",
		Asset: edge.From, AssetID: "1", AssetType: "ContactRecord", Edge: edge, Score: 0.9,
		Decision: ai.GapPropose, Signals: []string{"identity via phone"}}
	path := filepath.Join(t.TempDir(), "review.jsonl")
	if _, err := (&ai.Journal{Path: path}).SubmitOwnership([]ai.OwnershipProposal{p}); err != nil {
		t.Fatal(err)
	}

	return path, p
}

func TestApproveWritesOnceWithScoreAsConfidence(t *testing.T) {
	path, p := journalWithProposal(t)
	w := &fakeOwnershipWriter{}
	var out bytes.Buffer
	if err := approveProposal(context.Background(), w, path, p.ID, "", &out); err == nil {
		t.Error("approve without a reviewer was accepted")
	}
	if err := approveProposal(context.Background(), w, path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || w.writes[0] != p.Edge || w.confidence != 90 {
		t.Errorf("writes = %+v at confidence %d", w.writes, w.confidence)
	}
	if !strings.Contains(out.String(), "Wrote edge 77") {
		t.Errorf("output = %q", out.String())
	}
	if err := approveProposal(context.Background(), w, path, p.ID, "jeff", &out); err == nil || len(w.writes) != 1 {
		t.Error("an applied proposal was written again")
	}

	out.Reset()
	if err := listProposals(path, "text", &out); err != nil || !strings.Contains(out.String(), "applied by jeff") {
		t.Errorf("listing = %q, %v", out.String(), err)
	}
}

func TestRejectWritesNothing(t *testing.T) {
	path, p := journalWithProposal(t)
	var out bytes.Buffer
	if err := rejectProposal(path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}

	w := &fakeOwnershipWriter{}
	if err := approveProposal(context.Background(), w, path, p.ID, "jeff", &out); err == nil || len(w.writes) != 0 {
		t.Error("a rejected proposal was approved")
	}
}

type fakeRetractor struct {
	edges []string
}

func (f *fakeRetractor) RetractOwnership(_ context.Context, edgeID string) (bool, error) {
	f.edges = append(f.edges, edgeID)
	return true, nil
}

func TestRetractRemovesAppliedEdgeAndBlocksRewrites(t *testing.T) {
	path, p := journalWithProposal(t)
	var out bytes.Buffer
	r := &fakeRetractor{}
	if err := retractProposal(context.Background(), r, path, p.ID, "jeff", &out); err == nil {
		t.Error("a pending proposal was retracted")
	}
	if err := approveProposal(context.Background(), &fakeOwnershipWriter{}, path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}
	if err := retractProposal(context.Background(), r, path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}
	if len(r.edges) != 1 || r.edges[0] != "77" {
		t.Errorf("retracted edges = %v", r.edges)
	}

	state, err := (&ai.Journal{Path: path}).OwnershipState()
	if err != nil || state[p.ID].Status != ai.ProposalRetracted {
		t.Errorf("status = %+v, %v", state[p.ID], err)
	}
}
