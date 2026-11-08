// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeGraph struct {
	assets   map[string]Asset
	links    []Relation
	evidence map[string][]Evidence
}

func (g fakeGraph) GetAsset(_ context.Context, id string) (Asset, error) {
	a, ok := g.assets[id]
	if !ok {
		return Asset{}, errors.New("missing asset")
	}
	return a, nil
}
func (g fakeGraph) FindAssets(_ context.Context, kind string, _ time.Time, limit int) ([]Asset, error) {
	out := []Asset{}
	for _, a := range g.assets {
		if a.Type == kind {
			out = append(out, a)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
func (g fakeGraph) Edges(_ context.Context, id, dir, label string, _ time.Time) ([]Relation, error) {
	out := []Relation{}
	for _, r := range g.links {
		if label != "" && r.Label != label {
			continue
		}
		if (dir == "out" || dir == "both") && r.FromID == id {
			out = append(out, r)
		} else if (dir == "in" || dir == "both") && r.ToID == id {
			out = append(out, r)
		}
	}
	return out, nil
}
func (g fakeGraph) EdgesLimited(ctx context.Context, id, dir, label string, since time.Time, limit int) ([]Relation, bool, error) {
	edges, err := g.Edges(ctx, id, dir, label, since)
	if err != nil {
		return nil, false, err
	}
	if len(edges) > limit {
		return edges[:limit], true, nil
	}
	return edges, false, nil
}
func (g fakeGraph) EdgeEvidence(ctx context.Context,id string,limit int)([]Evidence,error){
 return g.Evidence(ctx,id,limit)
}
func (g fakeGraph) Evidence(_ context.Context, id string, limit int) ([]Evidence, error) {
	v := g.evidence[id]
	if len(v) > limit {
		v = v[:limit]
	}
	return v, nil
}
func graph() fakeGraph {
	return fakeGraph{assets: map[string]Asset{"a": {ID: "a", Type: "Organization", Key: "Acme"}, "b": {ID: "b", Type: "FQDN", Key: "acme.example"}, "c": {ID: "c", Type: "Service", Key: "svc"}}, links: []Relation{{ID: "e1", FromID: "a", ToID: "b", Label: "website"}, {ID: "e2", FromID: "b", ToID: "c", Label: "port"}}}
}
func TestWalkBoundAndDirection(t *testing.T) {
	l := DefaultLimits()
	l.MaxNodes = 2
	out, err := Walk(context.Background(), graph(), l, WalkRequest{StartID: "a", Depth: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated || len(out.Nodes) != 2 {
		t.Fatalf("expected bounded result: %+v", out)
	}
	_, err = Walk(context.Background(), graph(), l, WalkRequest{StartID: "a", Depth: 33})
	if err == nil {
		t.Fatal("unbounded depth accepted")
	}
	res, err := Walk(context.Background(), graph(), DefaultLimits(), WalkRequest{StartID: "c", Direction: "in", Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 3 {
		t.Fatalf("incoming walk: %+v", res)
	}
}
func TestRunnerRejectsUnknownFields(t *testing.T) {
	runner := ToolRunner{Graph: graph(), Limits: DefaultLimits()}
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
	candidate := Candidate{SubjectID: "a", ObjectID: "b", AllowedLabels: []string{"subsidiary"}, Evidence: []Evidence{
		{ID: "x", SourceID: "registry-A"}, {ID: "y", SourceID: "registry-B"}}}
	proposal := Proposal{SubjectID: "a", ObjectID: "b", Predicate: "subsidiary", Confidence: .9, Reason: "Evidence suggests a relationship", EvidenceIDs: []string{"x", "y"}}
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
	pairs, err := CandidatePairs([]Asset{{ID: "a", Type: "Organization", Key: "Acme, Inc."}, {ID: "b", Type: "Organization", Key: "ACME Ltd"}, {ID: "c", Type: "FQDN", Key: "acme.example"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("pairs=%+v", pairs)
	}
}

type fakeModel struct{ step int }

func (m *fakeModel) Generate(_ context.Context, _ []Message, _ []ToolSpec) (Response, error) {
	m.step++
	if m.step == 1 {
		return Response{Calls: []Call{{ID: "call-1", Name: "get_asset", Arguments: json.RawMessage(`{"id":"a"}`)}}}, nil
	}
	return Response{Text: "Found Organization asset a (Acme); ownership beyond this record is unverified."}, nil
}
func TestAgent(t *testing.T) {
	model := &fakeModel{}
	out, err := (Agent{Model: model, Runner: ToolRunner{Graph: graph(), Limits: DefaultLimits()}}).Ask(context.Background(), "What is a?")
	if err != nil {
		t.Fatal(err)
	}
	if out.ToolCalls != 1 || len(out.Observations) != 1 || !strings.Contains(out.Answer, "Acme") {
		t.Fatalf("unexpected answer %+v", out)
	}
}
func TestJournal(t *testing.T) {
	j := &Journal{Path: t.TempDir() + "/proposals.jsonl"}
	if err := j.Submit(Proposal{ID: "test", Status: "proposed"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Review("test", "accepted", "analyst"); err != nil {
		t.Fatal(err)
	}
	rows, err := j.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d", len(rows))
	}
}
func TestDiagramSanitizesLabels(t *testing.T) {
	got := Mermaid(WalkResult{Nodes: []Asset{{ID: "a", Type: "FQDN", Key: `demo.example\"<script>`}}})
	if strings.Contains(got, "<") || strings.Contains(got, "\"") && strings.Contains(got, "script>") {
		t.Fatalf("unsafe diagram: %q", got)
	}
}

type inferenceModel struct{ answer string }

func (m inferenceModel) Generate(_ context.Context, _ []Message, _ []ToolSpec) (Response, error) {
	return Response{Text: m.answer}, nil
}
func TestInferrerProposesReviewedOnly(t *testing.T) {
	c := Candidate{SubjectID: "org1", ObjectID: "org2", AllowedLabels: []string{"subsidiary"}, Evidence: []Evidence{
		{ID: "reg1", SourceID: "registry1"}, {ID: "lei2", SourceID: "gleif2"}}}
	model := inferenceModel{answer: `{"subject_id":"org1","predicate":"subsidiary","object_id":"org2","confidence":0.8,"reason":"Registry corroboration","evidence_ids":["reg1","lei2"],"contradictions":[]}`}
	p, err := (Inferrer{Model: model, Plugin: "example", ModelID: "test", MinSources: 2}).Analyze(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "proposed" || p.ID == "" || p.Model != "test" {
		t.Fatalf("bad proposal: %+v", p)
	}
	bad := inferenceModel{answer: `{"subject_id":"org1","predicate":"subsidiary","object_id":"org2","confidence":1,"reason":"guess","evidence_ids":["fake","lei2"]}`}
	if _, err := (Inferrer{Model: bad, MinSources: 2}).Analyze(context.Background(), c); err == nil {
		t.Fatal("invented evidence passed inference validation")
	}
}

// A model must inspect the database before answering an asset-specific question.
func TestAgentRequiresToolEvidence(t *testing.T) {
	m := inferenceModel{answer: "The domain belongs to the organization."}
	_, err := (Agent{Model: m, Runner: ToolRunner{Graph: graph(), Limits: DefaultLimits()}}).Ask(context.Background(), "Who owns the domain?")
	if err == nil {
		t.Fatal("ungrounded answer accepted")
	}
}

type failedToolModel struct{ step int }

func (m *failedToolModel) Generate(_ context.Context, _ []Message, _ []ToolSpec) (Response, error) {
	m.step++
	if m.step == 1 {
		return Response{Calls: []Call{{ID: "bad", Name: "get_asset", Arguments: json.RawMessage(`{"id":"not-in-db"}`)}}}, nil
	}
	return Response{Text: "The domain belongs to Acme."}, nil
}
func TestAgentRejectsAnswerAfterFailedTools(t *testing.T) {
	m := &failedToolModel{}
	_, err := (Agent{Model: m, Runner: ToolRunner{Graph: graph(), Limits: DefaultLimits()}}).Ask(context.Background(), "Who owns the domain?")
	if err == nil {
		t.Fatal("model supplied ungrounded answer following failed tool")
	}
}
