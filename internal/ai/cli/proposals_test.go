// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/ai/review"
)

type fakeOwnershipWriter struct {
	writes     []lens.ProposedEdge
	confidence int
}

func (f *fakeOwnershipWriter) ApplyOwnership(_ context.Context, e lens.ProposedEdge, confidence int) (string, bool, error) {
	f.writes = append(f.writes, e)
	f.confidence = confidence
	return "77", false, nil
}

func journalWithProposal(t *testing.T) (string, review.OwnershipProposal) {
	t.Helper()

	edge := lens.ProposedEdge{FromID: "1", FromType: "ContactRecord", From: "https://rdap.example/alumni",
		Label: "organization", RelationType: "SimpleRelation", ToID: "2", ToType: "Organization",
		To: "Synthetic University"}
	p := review.OwnershipProposal{ID: review.ProposalID(edge), Owner: "Synthetic University", OwnerID: "2",
		Asset: edge.From, AssetID: "1", AssetType: "ContactRecord", Edge: edge, Score: 0.9,
		Decision: lens.GapPropose, Signals: []string{"identity via phone"}}
	path := filepath.Join(t.TempDir(), "review.jsonl")
	if _, err := (&review.Journal{Path: path}).SubmitOwnership([]review.OwnershipProposal{p}); err != nil {
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
	if err := listProposals(path, "json", false, &out); err != nil || !strings.Contains(out.String(), "applied by jeff") {
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

	state, err := (&review.Journal{Path: path}).OwnershipState()
	if err != nil || state[p.ID].Status != review.ProposalRetracted {
		t.Errorf("status = %+v, %v", state[p.ID], err)
	}
}

type adviceModel struct{}

func (adviceModel) Generate(_ context.Context, _ []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	return llm.Response{Text: "RECOMMENDATION: reject\nThe only link is shared hosting [E1]."}, nil
}

func TestReviewRecordsAdviceWithoutDeciding(t *testing.T) {
	_, p := journalWithProposal(t)
	p.Witness = []graph.WitnessEdge{{FromType: "FQDN", From: "alumni.example", Label: "dns_record", ToType: "IPAddress",
		To: "192.0.2.1"}}
	path := filepath.Join(t.TempDir(), "review.jsonl")
	j := &review.Journal{Path: path}
	if _, err := j.SubmitOwnership([]review.OwnershipProposal{p}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := reviewProposals(context.Background(), ai.Agent{Model: adviceModel{}}, "test-model", path, "", 10,
		&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "advice from test-model: reject.") {
		t.Errorf("output = %q", out.String())
	}

	state, err := j.OwnershipState()
	if err != nil || state[p.ID].Status != review.ProposalPending || state[p.ID].Advice == nil {
		t.Fatalf("state = %+v, %v", state[p.ID], err)
	}

	out.Reset()
	if err := reviewProposals(context.Background(), ai.Agent{Model: adviceModel{}}, "test-model", path, "", 10,
		&out); err != nil || !strings.Contains(out.String(), "No pending proposals need advice") {
		t.Errorf("second review = %q, %v", out.String(), err)
	}
}

func TestTrainAttributionWritesALoadableModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review.jsonl")
	j := &review.Journal{Path: path}
	for i := 0; i < 90; i++ {
		edge := lens.ProposedEdge{FromID: fmt.Sprint(i), Label: "organization", RelationType: "SimpleRelation", ToID: "o"}
		p := review.OwnershipProposal{ID: review.ProposalID(edge), Edge: edge}
		outcome := review.OwnershipOutcome{ProposalID: p.ID, Status: review.ProposalApplied, Reviewer: "jeff", EdgeID: "e"}
		if i%2 == 0 {
			p.Signals = []string{"identity via ContactRecord phone Phone", "identity via ContactRecord location Location"}
		} else {
			p.Signals = []string{"hosting via FQDN dns_record IPAddress"}
			outcome.Status, outcome.EdgeID = review.ProposalRejected, ""
		}
		if _, err := j.SubmitOwnership([]review.OwnershipProposal{p}); err != nil {
			t.Fatal(err)
		}
		if err := j.RecordOwnership(outcome); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	if err := trainAttribution(path, "", &out); err != nil {
		t.Fatal(err)
	}

	m, err := ai.LoadAttributionModel(ai.AttributionModelPath(path))
	if err != nil || m == nil || m.Task != ai.OwnershipTask {
		t.Fatalf("model = %+v, %v", m, err)
	}
	if !strings.Contains(out.String(), "the engine uses it from the next enumeration") {
		t.Errorf("output = %q", out.String())
	}
}

func TestTrainAttributionNeedsEnoughReviews(t *testing.T) {
	path, _ := journalWithProposal(t)
	if err := trainAttribution(path, "", &bytes.Buffer{}); err == nil {
		t.Error("a model was trained from one pending proposal")
	}
}

func TestSignalsExplainEachRule(t *testing.T) {
	var out bytes.Buffer
	if err := listSignals("json", false, &out); err != nil {
		t.Fatal(err)
	}
	for _, s := range lens.OwnershipSignals() {
		if !strings.Contains(out.String(), s.Title+" ("+s.ID+")") || !strings.Contains(out.String(), s.Rationale) {
			t.Errorf("text listing lacks %s or its rationale", s.ID)
		}
	}

	out.Reset()
	if err := listSignals("markdown", true, &out); err != nil || out.String() != lens.SignalsMarkdown() {
		t.Errorf("markdown listing differs from SIGNALS.md source: %v", err)
	}
	if err := listSignals("mermaid", true, &out); err == nil {
		t.Error("an unsupported format was accepted")
	}
}
