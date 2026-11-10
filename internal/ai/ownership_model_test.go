// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

func TestOwnershipFeaturesFromSignals(t *testing.T) {
	p := OwnershipProposals(gapReport(t))[0]
	f := OwnershipFeatures(p)
	want := map[string]float64{"identity": 1, "identity:Phone": 1, "identity:Location": 1, "kinds": 1.0 / 3,
		"gains": 0.2}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("feature %s = %v, want %v (all: %v)", k, f[k], v, f)
		}
	}
}

func TestOwnershipLabelsComeFromPeopleOnly(t *testing.T) {
	cases := []struct {
		status, reviewer, label string
		ok                      bool
	}{
		{ProposalApplied, "jeff", "potential_relation", true},
		{ProposalApplied, AutomaticReviewer, "", false},
		{ProposalRejected, "jeff", "unrelated", true},
		{ProposalRetracted, "jeff", "unrelated", true},
		{ProposalPending, "", "", false},
	}
	for _, c := range cases {
		e := OwnershipEntry{Status: c.status}
		if c.reviewer != "" {
			e.Outcome = &OwnershipOutcome{Status: c.status, Reviewer: c.reviewer}
		}

		label, ok := OwnershipLabel(e)
		if label != c.label || ok != c.ok {
			t.Errorf("%s by %q = %q, %v", c.status, c.reviewer, label, ok)
		}
	}
}

// reviewedJournal returns entries a reviewer decided: shared registrant
// details approved, hosting or co-listing alone rejected.
func reviewedJournal(n int) []OwnershipEntry {
	var out []OwnershipEntry
	for i := 0; i < n; i++ {
		p := OwnershipProposal{ID: fmt.Sprintf("own-%04d", i)}
		status := ProposalApplied
		switch i % 3 {
		case 0:
			p.Signals = []string{"identity via ContactRecord phone Phone",
				"identity via ContactRecord location Location"}
		case 1:
			p.Signals = []string{"identity via ContactRecord phone Phone", "hosting via FQDN dns_record IPAddress"}
		default:
			p.Signals = []string{"hosting via FQDN dns_record IPAddress", "colisting via TLSCertificate san_dns_name"}
			status = ProposalRejected
		}

		out = append(out, OwnershipEntry{Proposal: p, Status: status,
			Outcome: &OwnershipOutcome{Status: status, Reviewer: "jeff"}})
	}

	return out
}

func trainedOwnershipModel(t *testing.T) *classify.LinearModel {
	t.Helper()

	rows, spec := OwnershipTrainingSet(reviewedJournal(90))
	m, metrics, err := TrainOwnershipModel(rows, spec, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.HoldoutAccuracy < 0.95 {
		t.Fatalf("holdout accuracy %.2f", metrics.HoldoutAccuracy)
	}

	return m
}

func TestOwnershipModelLearnsFromReviews(t *testing.T) {
	m := trainedOwnershipModel(t)
	strong := OwnershipProposal{Signals: []string{"identity via ContactRecord phone Phone",
		"identity via ContactRecord location Location"}}
	weak := OwnershipProposal{Signals: []string{"hosting via FQDN dns_record IPAddress"}}

	ps, err := ownershipProbability(m, strong)
	if err != nil {
		t.Fatal(err)
	}

	pw, err := ownershipProbability(m, weak)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("strong %.3f, weak %.3f, threshold %.3f", ps, pw, m.ReviewThreshold)
	if m.ReviewThreshold < minOwnershipThreshold || ps < m.ReviewThreshold || pw >= m.ReviewThreshold {
		t.Errorf("strong %.3f, weak %.3f against threshold %.3f", ps, pw, m.ReviewThreshold)
	}
}

func TestAttributeOwnershipDecidesWithTheModel(t *testing.T) {
	m := trainedOwnershipModel(t)
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	w := &recordingWriter{}
	res := attributeWith(t, w, j, AttributionPolicy{Mode: "auto", Model: m})
	if len(res.Applied) != 1 || res.Applied[0].Proposal.ModelID != "test-model" {
		t.Fatalf("applied = %+v", res.Applied)
	}
	if c := ProposalConfidence(res.Applied[0].Proposal); c != int(res.Applied[0].Proposal.ModelScore*100+0.5) {
		t.Errorf("confidence %d does not come from the model score %.3f", c, res.Applied[0].Proposal.ModelScore)
	}

	// A model that has learned to distrust everything writes nothing.
	m.ReviewThreshold = 1
	j2 := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if res := attributeWith(t, &recordingWriter{}, j2, AttributionPolicy{Mode: "auto", Model: m}); len(res.Applied) != 0 ||
		len(res.Queued) != 1 {
		t.Errorf("with an unreachable threshold: applied %d, queued %d", len(res.Applied), len(res.Queued))
	}
}

func TestOwnershipModelRefusesIndistinctReviews(t *testing.T) {
	entries := reviewedJournal(90)
	for i := range entries {
		// The same evidence approved and rejected: nothing to learn.
		entries[i].Proposal.Signals = []string{"identity via ContactRecord phone Phone"}
	}

	rows, spec := OwnershipTrainingSet(entries)
	if _, _, err := TrainOwnershipModel(rows, spec, "confused"); err == nil {
		t.Error("a model was trained from contradictory reviews")
	}
}
