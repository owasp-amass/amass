// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

func TestAdjudicatorKinds(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range AdjudicatorKinds() {
		if k.Name == "" || k.Task == "" || k.FeatureVersion == "" || k.File == "" || k.Examples == nil ||
			k.MinExamples <= 0 || k.MinPrecision <= 0 || k.MinThreshold <= 0 {
			t.Errorf("kind %+v is incomplete", k)
		}
		if seen[k.File] {
			t.Errorf("two kinds share the file %s", k.File)
		}
		seen[k.File] = true
		if got, ok := LookupAdjudicatorKind(k.Name); !ok || got != k {
			t.Errorf("lookup %s", k.Name)
		}
	}
	if _, ok := LookupAdjudicatorKind("nope"); ok {
		t.Error("an unknown kind was found")
	}
}

// Only people's decisions on domain expansions are horizontal labels.
func TestHorizontalExamples(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	for _, e := range []review.ScopeExpansion{
		{OrgID: "o", Asset: "a.example", SignalIDs: []string{lens.SigCertSubjectOrg}, Confidence: 60,
			Status: review.ProposalApplied, Reviewer: "jeff"},
		{OrgID: "o", Asset: "b.example", Status: review.ProposalRejected, Reviewer: "jeff"},
		{OrgID: "o", Asset: "c.example", Status: review.ProposalRetracted, Reviewer: "jeff"},
		{OrgID: "o", Asset: "d.example", Status: review.ProposalApplied, Reviewer: review.AutomaticReviewer},
		{OrgID: "o", Asset: "e.example", Status: review.ProposalRetracted, Reviewer: review.RecheckReviewer},
		{OrgID: "o", Asset: "f.example", Status: review.ProposalPending},
		{OrgID: "o", AssetType: "Netblock", Asset: "192.0.2.0/24", Status: review.ProposalApplied, Reviewer: "jeff"},
	} {
		if err := j.RecordScopeExpansion(e); err != nil {
			t.Fatal(err)
		}
	}

	rows, features, err := horizontalExamples(j)
	if err != nil {
		t.Fatal(err)
	}
	var pos, neg int
	for _, r := range rows {
		if r.Label == labelPositive {
			pos++
		} else {
			neg++
		}
	}
	if pos != 1 || neg != 2 || len(features) == 0 {
		t.Errorf("rows %+v, features %v", rows, features)
	}

	if _, _, err := HorizontalKind.TrainFromJournal(j, "few"); err == nil {
		t.Error("a model was trained from three labels")
	}
}

// A horizontal model trained from people's decisions decides the domains
// with the signals they approved and none they turned down.
func TestHorizontalKindTrains(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	for i := 0; i < 60; i++ {
		e := review.ScopeExpansion{OrgID: "o", Asset: fmt.Sprintf("d%d.example", i), Reviewer: "jeff"}
		if i%2 == 0 {
			e.SignalIDs, e.Confidence, e.Status = []string{lens.SigCertSubjectOrg, lens.SigRegistrantOrg}, 70,
				review.ProposalApplied
		} else {
			e.SignalIDs, e.Confidence, e.Status = []string{lens.SigSharedNameServer}, 40, review.ProposalRejected
		}
		if err := j.RecordScopeExpansion(e); err != nil {
			t.Fatal(err)
		}
	}

	m, _, err := HorizontalKind.TrainFromJournal(j, "horizontal-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := HorizontalKind.Save(m, HorizontalKind.Path(j.Path)); err != nil {
		t.Fatal(err)
	}
	s, err := LoadHorizontalScorer(j)
	if err != nil || s == nil {
		t.Fatalf("scorer %v, %v", s, err)
	}

	hit, _ := s.Probability([]string{lens.SigCertSubjectOrg, lens.SigRegistrantOrg}, 70)
	miss, _ := s.Probability([]string{lens.SigSharedNameServer}, 40)
	if hit < s.Threshold() || miss >= s.Threshold() || s.Threshold() < HorizontalKind.MinThreshold {
		t.Errorf("approved %.2f, rejected %.2f, threshold %.2f", hit, miss, s.Threshold())
	}
}

// The main model's confident admissions of domains, and its confident
// rejections kept as advice on pending ones, teach the horizontal
// classifier; the classifier's, the rules', weak, retracted or
// person-decided ones do not.
func TestHorizontalModelExamples(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	for _, e := range []review.ScopeExpansion{
		{OrgID: "o", Asset: "a.example", SignalIDs: []string{lens.SigCertSubjectOrg}, Status: review.ProposalApplied,
			Reviewer: "amass-ai (model anthropic/test)", DecidedConfidence: 92},
		{OrgID: "o", Asset: "b.example", Status: review.ProposalApplied, Reviewer: "amass-ai (model anthropic/test)",
			DecidedConfidence: 85},
		{OrgID: "o", Asset: "c.example", Status: review.ProposalApplied, Reviewer: "amass-ai (classifier h-1)",
			DecidedConfidence: 99},
		{OrgID: "o", Asset: "d.example", Status: review.ProposalApplied, Reviewer: review.AutomaticReviewer},
		{OrgID: "o", Asset: "e.example", Status: review.ProposalApplied, Reviewer: "amass-ai (model anthropic/test)",
			DecidedConfidence: 95},
		{OrgID: "o", Asset: "e.example", Status: review.ProposalRetracted, Reviewer: "jeff"},
		{OrgID: "o", Asset: "f.example", SignalIDs: []string{lens.SigSharedNameServer}, Status: review.ProposalPending,
			Advice: &review.ScopeAdvice{Model: "model anthropic/test", Decision: review.ScopeAdviceReject, Confidence: 93}},
		{OrgID: "o", Asset: "g.example", Status: review.ProposalPending,
			Advice: &review.ScopeAdvice{Model: "model anthropic/test", Decision: review.ScopeAdviceAdmit, Confidence: 95}},
		{OrgID: "o", Asset: "h.example", Status: review.ProposalPending,
			Advice: &review.ScopeAdvice{Model: "model anthropic/test", Decision: review.ScopeAdviceReject, Confidence: 80}},
		{OrgID: "o", Asset: "i.example", Status: review.ProposalPending,
			Advice: &review.ScopeAdvice{Model: "classifier h-1", Decision: review.ScopeAdviceReject, Confidence: 99}},
		{OrgID: "o", Asset: "j.example", Status: review.ProposalPending,
			Advice: &review.ScopeAdvice{Model: "model anthropic/test", Decision: review.ScopeAdviceReject, Confidence: 95}},
		{OrgID: "o", Asset: "j.example", Status: review.ProposalApplied, Reviewer: "jeff"},
	} {
		if err := j.RecordScopeExpansion(e); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := horizontalModelExamples(j)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, r := range rows {
		switch {
		case r.Features["signal:"+lens.SigCertSubjectOrg] == 1:
			labels["a"] = r.Label
		case r.Features["signal:"+lens.SigSharedNameServer] == 1:
			labels["f"] = r.Label
		}
	}
	if len(rows) != 2 || labels["a"] != labelPositive || labels["f"] != labelNegative {
		t.Errorf("rows %+v", rows)
	}
	if p, n, m, err := HorizontalKind.LabelCounts(j); err != nil || p != 1 || n != 1 || m != 2 {
		t.Errorf("label counts %d/%d/%d, %v", p, n, m, err)
	}
}
