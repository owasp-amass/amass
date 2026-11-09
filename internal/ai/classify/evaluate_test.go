// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"context"
	"strings"
	"testing"
)

func TestEvaluateTriageMetrics(t *testing.T) {
	model, err := Load(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	cases := []LabeledCase{
		{ID: "true-negative", Input: Input{Task: model.Task, Features: map[string]float64{"verified_negative": 1}}, ExpectedLabel: "unrelated"},
		{ID: "true-positive", Input: Input{Task: model.Task, Features: map[string]float64{"legal_record_match": 1}}, ExpectedLabel: "potential_relation"},
		{ID: "abstain", Input: Input{Task: model.Task, Features: map[string]float64{"legal_record_match": .5, "verified_negative": .5}}, ExpectedLabel: "potential_relation"},
		{ID: "false-skip", Input: Input{Task: model.Task, Features: map[string]float64{"verified_negative": 1}}, ExpectedLabel: "potential_relation"},
	}
	got, err := Evaluate(context.Background(), model, cases)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 4 || got.Skipped != 2 || got.Reviewed != 1 || got.Escalated != 1 || got.UnsafeSkips != 1 || got.Correct != 2 {
		t.Fatalf("incorrect evaluation metrics: %+v", got)
	}
}
func TestEvaluateRejectsDuplicatedGroundTruth(t *testing.T) {
	model, _ := Load(strings.NewReader(fixture))
	cases := []LabeledCase{{ID: "x", Input: Input{Task: model.Task, Features: map[string]float64{"verified_negative": 1}}, ExpectedLabel: "unrelated"}}
	cases = append(cases, cases[0])
	if _, err := Evaluate(context.Background(), model, cases); err == nil {
		t.Fatal("duplicated held-out case accepted")
	}
}
