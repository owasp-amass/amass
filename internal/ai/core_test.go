// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/review"
)

func TestRunnerRejectsUnknownFields(t *testing.T) {
	runner := ToolRunner{Graph: graphtest.SampleGraph(), Limits: graph.DefaultLimits()}
	_, err := runner.Run(context.Background(), "get_asset", json.RawMessage(`{"id":"a","injection":"x"}`))
	if err == nil {
		t.Fatal("unknown field accepted")
	}

	_, err = runner.Run(context.Background(), "execute_sql", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("unexpected tool accepted")
	}
}

func TestInferenceRejectsFakeEvidenceAndSources(t *testing.T) {
	candidate := review.Candidate{SubjectID: "a", ObjectID: "b", AllowedLabels: []string{"subsidiary"}, Evidence: []graph.Evidence{
		{ID: "x", SourceID: "registry-A"}, {ID: "y", SourceID: "registry-B"}}}
	proposal := review.Proposal{
		SubjectID:   "a",
		ObjectID:    "b",
		Predicate:   "subsidiary",
		Confidence:  .9,
		Reason:      "Evidence suggests a relationship",
		EvidenceIDs: []string{"x", "y"},
	}
	if err := ValidateCandidate(candidate, proposal, 2); err != nil {
		t.Fatal(err)
	}

	proposal.EvidenceIDs = []string{"x", "invented"}
	if err := ValidateCandidate(candidate, proposal, 2); err == nil {
		t.Fatal("invented evidence accepted")
	}

	proposal.EvidenceIDs = []string{"x", "y"}
	candidate.Evidence[1].SourceID = "registry-A"
	if err := ValidateCandidate(candidate, proposal, 2); err == nil {
		t.Fatal("duplicate source accepted")
	}
}

func TestCandidatePairs(t *testing.T) {
	pairs, err := CandidatePairs([]graph.Asset{
		{ID: "a", Type: "Organization", Key: "Acme, Inc."},
		{ID: "b", Type: "Organization", Key: "ACME Ltd"},
		{ID: "c", Type: "FQDN", Key: "acme.example"},
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("pairs=%+v", pairs)
	}
}

type fakeModel struct{ step int }

func (m *fakeModel) Generate(_ context.Context, _ []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	m.step++
	if m.step == 1 {
		return llm.Response{Calls: []llm.Call{{ID: "call-1", Name: "get_asset", Arguments: json.RawMessage(`{"id":"a"}`)}}}, nil
	}

	return llm.Response{Text: "Found Organization asset a (Acme); ownership beyond this record is unverified."}, nil
}

func TestAgent(t *testing.T) {
	model := &fakeModel{}
	out, err := (Agent{
		Model:  model,
		Runner: ToolRunner{Graph: graphtest.SampleGraph(), Limits: graph.DefaultLimits()},
	}).Ask(context.Background(), "What is a?")
	if err != nil {
		t.Fatal(err)
	}
	if out.ToolCalls != 1 || len(out.Observations) != 1 || !strings.Contains(out.Answer, "Acme") {
		t.Fatalf("unexpected answer %+v", out)
	}
}

func TestDiagramSanitizesLabels(t *testing.T) {
	got := Mermaid(graph.WalkResult{Nodes: []graph.Asset{{ID: "a", Type: "FQDN", Key: `demo.example\"<script>`}}})
	if strings.Contains(got, "<") || strings.Contains(got, "\"") && strings.Contains(got, "script>") {
		t.Fatalf("unsafe diagram: %q", got)
	}
}

type inferenceModel struct{ answer string }

func (m inferenceModel) Generate(_ context.Context, _ []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	return llm.Response{Text: m.answer}, nil
}

func TestInferrerProposesReviewedOnly(t *testing.T) {
	c := review.Candidate{SubjectID: "org1", ObjectID: "org2", AllowedLabels: []string{"subsidiary"}, Evidence: []graph.Evidence{
		{ID: "reg1", SourceID: "registry1"}, {ID: "lei2", SourceID: "gleif2"}}}
	model := inferenceModel{
		answer: `{"subject_id":"org1","predicate":"subsidiary","object_id":"org2","confidence":0.8,"reason":"Registry corroboration","evidence_ids":["reg1","lei2"],"contradictions":[]}`,
	}
	p, err := (Inferrer{
		Model:      model,
		Plugin:     "example",
		ModelID:    "test",
		MinSources: 2,
	}).Analyze(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "proposed" || p.ID == "" || p.Model != "test" {
		t.Fatalf("bad proposal: %+v", p)
	}

	bad := inferenceModel{
		answer: `{"subject_id":"org1","predicate":"subsidiary","object_id":"org2","confidence":1,"reason":"guess","evidence_ids":["fake","lei2"]}`,
	}
	if _, err := (Inferrer{Model: bad, MinSources: 2}).Analyze(context.Background(), c); err == nil {
		t.Fatal("invented evidence passed inference validation")
	}
}

// A model must inspect the database before answering an asset-specific question.
func TestAgentRequiresToolEvidence(t *testing.T) {
	m := inferenceModel{answer: "The domain belongs to the organization."}
	_, err := (Agent{
		Model:  m,
		Runner: ToolRunner{Graph: graphtest.SampleGraph(), Limits: graph.DefaultLimits()},
	}).Ask(context.Background(), "Who owns the domain?")
	if err == nil {
		t.Fatal("ungrounded answer accepted")
	}
}

type failedToolModel struct{ step int }

func (m *failedToolModel) Generate(_ context.Context, _ []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	m.step++
	if m.step == 1 {
		return llm.Response{
			Calls: []llm.Call{{ID: "bad", Name: "get_asset", Arguments: json.RawMessage(`{"id":"not-in-db"}`)}},
		}, nil
	}

	return llm.Response{Text: "The domain belongs to Acme."}, nil
}

func TestAgentRejectsAnswerAfterFailedTools(t *testing.T) {
	m := &failedToolModel{}
	_, err := (Agent{
		Model:  m,
		Runner: ToolRunner{Graph: graphtest.SampleGraph(), Limits: graph.DefaultLimits()},
	}).Ask(context.Background(), "Who owns the domain?")
	if err == nil {
		t.Fatal("model supplied ungrounded answer following failed tool")
	}
}

type collidingEvidenceGraph struct{ graphtest.FakeGraph }

func (g collidingEvidenceGraph) Evidence(ctx context.Context, id string, limit int) ([]graph.Evidence, error) {
	return []graph.Evidence{{ID: "asset-tag", SubjectID: id, SourceID: "asset-only", Kind: "SourceProperty"}}, nil
}

func (g collidingEvidenceGraph) EdgeEvidence(ctx context.Context, id string, limit int) ([]graph.Evidence, error) {
	return []graph.Evidence{{ID: "edge-tag", SubjectID: id, SourceID: "edge-only", Kind: "SourceProperty"}}, nil
}

func TestGetEdgeEvidenceUsesExactRelationNamespace(t *testing.T) {
	runner := ToolRunner{Graph: collidingEvidenceGraph{FakeGraph: graphtest.SampleGraph()}, Limits: graph.DefaultLimits()}
	raw, err := runner.Run(context.Background(), "get_edge_evidence", json.RawMessage(`{"id":"1","limit":8}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "edge-tag") || strings.Contains(string(raw), "asset-tag") {
		t.Fatalf("typed edge evidence returned asset tags for colliding identifier: %s", raw)
	}

	t.Logf("exact edge evidence with colliding ID: %s", raw)
}
