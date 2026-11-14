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
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

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
