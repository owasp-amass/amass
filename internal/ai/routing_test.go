// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"errors"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

type routingClassifier struct {
	prediction classify.Prediction
	count      int
}

func (m *routingClassifier) Classify(_ context.Context, in classify.Input) (classify.Prediction, error) {
	m.count++
	if in.Task != OrganizationClassificationTask || in.Features["distinct_sources"] <= 0 {
		return classify.Prediction{}, errors.New("invalid features")
	}
	p := m.prediction
	p.FeatureVersion = OrganizationFeatureVersion
	return p, nil
}

type routingGenerative struct{ calls int }

func (m *routingGenerative) Generate(_ context.Context, _ []Message, _ []ToolSpec) (Response, error) {
	m.calls++
	return Response{Text: `{"subject_id":"a","predicate":"subsidiary","object_id":"b","confidence":0.78,"reason":"Synthetic sources","evidence_ids":["e1","e2"],"contradictions":[]}`}, nil
}
func routedCandidate() Candidate {
	return Candidate{
		SubjectID: "a", ObjectID: "b", AllowedLabels: []string{"subsidiary"},
		Evidence: []Evidence{{ID: "e1", SourceID: "registry", Kind: "SourceProperty"}, {ID: "e2", SourceID: "lei", Kind: "SourceProperty"}},
	}
}
func TestFeatureProvenanceCountsUniqueSources(t *testing.T) {
	c := routedCandidate()
	c.Evidence = append(c.Evidence, Evidence{ID: "e3", SourceID: "registry", Kind: "SourceProperty"})
	in, summary, err := ExtractProvenanceFeatures(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.SourceIDs) != 2 || in.Features["distinct_sources"] != 2.0/3.0 {
		t.Fatalf("got %+v %+v", in, summary)
	}
	c.Evidence = append(c.Evidence, Evidence{ID: "e2", SourceID: "different"})
	if _, _, err := ExtractProvenanceFeatures(c); err == nil {
		t.Fatal("conflicting source accepted")
	}
}
func TestUnattributedEvidenceNeverCountsTowardMinimum(t *testing.T) {
	c := routedCandidate()
	c.Evidence[1].SourceID = ""
	local := &routingClassifier{}
	model := &routingGenerative{}
	result, err := (Inferrer{Model: model, MinSources: 2}).AnalyzeRouted(context.Background(), c, local, RoutingPolicy{AllowLocalReview: true})
	if err != nil || result.Decision != "needs_evidence" || local.count != 0 || model.calls != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
func TestUncalibratedSkipAlwaysEscalates(t *testing.T) {
	local := &routingClassifier{prediction: classify.Prediction{Decision: "skip", ScoreKind: "uncalibrated_softmax"}}
	model := &routingGenerative{}
	result, err := (Inferrer{Model: model, MinSources: 2, Plugin: "test", ModelID: "test"}).AnalyzeRouted(context.Background(), routedCandidate(), local, RoutingPolicy{AllowCalibratedSkip: true})
	if err != nil || result.Decision != "proposed" || model.calls != 1 || result.Proposal == nil {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, model.calls)
	}
}
func TestLocalReviewNeverCreatesProposal(t *testing.T) {
	local := &routingClassifier{prediction: classify.Prediction{Decision: "review", ScoreKind: "uncalibrated_softmax"}}
	model := &routingGenerative{}
	result, err := (Inferrer{Model: model, MinSources: 2}).AnalyzeRouted(context.Background(), routedCandidate(), local, RoutingPolicy{AllowLocalReview: true})
	if err != nil || result.Decision != "review" || result.Proposal != nil || model.calls != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
func TestSkipRequiresCalibratedAndPolicy(t *testing.T) {
	local := &routingClassifier{prediction: classify.Prediction{Decision: "skip", ScoreKind: "calibrated_probability"}}
	model := &routingGenerative{}
	result, err := (Inferrer{Model: model, MinSources: 2}).AnalyzeRouted(context.Background(), routedCandidate(), local, RoutingPolicy{AllowCalibratedSkip: true})
	if err != nil || result.Decision != "skip" || model.calls != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	result, err = (Inferrer{Model: model, MinSources: 2}).AnalyzeRouted(context.Background(), routedCandidate(), local, RoutingPolicy{})
	if err != nil || result.Decision != "proposed" || model.calls != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
func TestNoModelEscalationMarked(t *testing.T) {
	c := routedCandidate()
	result, err := (Inferrer{MinSources: 2}).AnalyzeRouted(context.Background(), c, nil, RoutingPolicy{})
	if err != nil || result.Decision != "escalate" || result.UsedGenerativeModel {
		t.Fatalf("%+v %v", result, err)
	}
}

type wrongVersionClassifier struct{}

func (wrongVersionClassifier) Classify(context.Context, classify.Input) (classify.Prediction, error) {
	return classify.Prediction{Label: "potential_relation", ScoreKind: "uncalibrated_softmax", Decision: "review", FeatureVersion: "wrong"}, nil
}
func TestRejectIncompatibleFeatureSchema(t *testing.T) {
	model := &routingGenerative{}
	_, err := (Inferrer{MinSources: 2, Model: model}).AnalyzeRouted(context.Background(), routedCandidate(), wrongVersionClassifier{}, RoutingPolicy{AllowLocalReview: true})
	if err == nil || model.calls != 0 {
		t.Fatalf("feature schema mismatch accepted, err=%v, calls=%d", err, model.calls)
	}
}

// A graph without server-side bounded reads must not be traversed by an agent.
type legacyUnboundedGraph struct{ Graph }

func TestWalkRequiresBoundedReader(t *testing.T) {
	_, err := Walk(context.Background(), legacyUnboundedGraph{Graph: graph()}, DefaultLimits(), WalkRequest{StartID: "a"})
	if err == nil {
		t.Fatal("agent accepted unbounded graph traversal")
	}
}

func TestDefaultEvidenceClassifierRoutesObservedOAMDataWithoutLLM(t *testing.T) {
	model := &routingGenerative{}
	c := routedCandidate()
	result, err := (Inferrer{Model: model, MinSources: 2, Plugin: "test", ModelID: "test"}).AnalyzeRouted(
		context.Background(), c, classify.EvidenceRuleClassifier{}, RoutingPolicy{AllowLocalReview: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "review" || result.Prediction == nil || result.Prediction.ScoreKind != "rules_no_probability" ||
		result.Proposal != nil || model.calls != 0 || result.UsedGenerativeModel {
		t.Fatalf("default classifier must route real source-tag observations to review, not LLM/OAM writes: %+v model_calls=%d", result, model.calls)
	}
	if len(result.Provenance.SourceIDs) != 2 {
		t.Fatalf("lost stored evidence sources: %+v", result.Provenance)
	}
}
