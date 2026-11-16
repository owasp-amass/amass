// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

type fakeScorer struct {
	probs     map[string]float64
	threshold float64
}

func (f fakeScorer) ModelName() string                                { return "test-model" }
func (f fakeScorer) Threshold() float64                               { return f.threshold }
func (f fakeScorer) Probability(p OwnershipProposal) (float64, error) { return f.probs[p.AssetID], nil }

func edgeTo(id string) *lens.ProposedEdge {
	return &lens.ProposedEdge{FromID: "c-" + id, FromType: "ContactRecord", Label: "organization",
		RelationType: "SimpleRelation", ToID: "org1", ToType: "Organization"}
}

func TestScoreGapCandidates(t *testing.T) {
	report := &lens.OwnershipGapReport{
		Owner: graph.Asset{ID: "org1", Type: "Organization"},
		Candidates: []lens.GapCandidate{
			{AssetID: "a1", Type: "FQDN", Asset: "a1.example.com", Decision: lens.GapReview, Score: 0.4, Attachment: edgeTo("a1")},
			{AssetID: "a2", Type: "FQDN", Asset: "a2.example.com", Decision: lens.GapReview, Score: 0.4, Attachment: edgeTo("a2")},
			{AssetID: "a3", Type: "FQDN", Asset: "a3.example.com", Decision: lens.GapWeak, Score: 0.1, Attachment: edgeTo("a3")},
			{AssetID: "a4", Type: "FQDN", Asset: "a4.example.com", Decision: lens.GapReview, Score: 0.4,
				Attachment: edgeTo("a4"), Alternatives: []lens.ProposedEdge{*edgeTo("a4b")}},
		},
	}

	scorer := fakeScorer{threshold: 0.7, probs: map[string]float64{"a1": 0.9, "a2": 0.5, "a3": 0.95, "a4": 0.95}}
	if err := ScoreGapCandidates(report, scorer); err != nil {
		t.Fatal(err)
	}

	// Above the threshold: proposed, scored by the model.
	if c := report.Candidates[0]; c.Decision != lens.GapPropose || c.Score != 0.9 {
		t.Errorf("a1 = %s %v, want propose 0.9", c.Decision, c.Score)
	}
	// Below the threshold: review, scored by the model.
	if c := report.Candidates[1]; c.Decision != lens.GapReview || c.Score != 0.5 {
		t.Errorf("a2 = %s %v, want review 0.5", c.Decision, c.Score)
	}
	// Weak: the model never writes it, so the rules' decision and score stand.
	if c := report.Candidates[2]; c.Decision != lens.GapWeak || c.Score != 0.1 {
		t.Errorf("a3 (weak) was changed: %s %v", c.Decision, c.Score)
	}
	// Ambiguous (alternatives): left to the rules.
	if c := report.Candidates[3]; c.Decision != lens.GapReview || c.Score != 0.4 {
		t.Errorf("a4 (ambiguous) was changed: %s %v", c.Decision, c.Score)
	}

	// A nil scorer leaves the report untouched.
	before := report.Candidates[0].Score
	if err := ScoreGapCandidates(report, nil); err != nil || report.Candidates[0].Score != before {
		t.Errorf("nil scorer changed the report: %v", err)
	}
}
