// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

func TestReviewTriageJournalNeverCreatesProposal(t *testing.T) {
	local := &routingClassifier{prediction: classify.Prediction{Decision: "review", ModelID: "classifier-1", ScoreKind: "uncalibrated_softmax"}}
	c := routedCandidate()
	result, err := (Inferrer{MinSources: 2}).AnalyzeRouted(context.Background(), c, local, RoutingPolicy{AllowLocalReview: true})
	if err != nil {
		t.Fatal(err)
	}
	j := &Journal{Path: t.TempDir() + "/journal.jsonl"}
	if err := j.SubmitTriage(c, result); err != nil {
		t.Fatal(err)
	}
	entries, err := j.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d", len(entries))
	}
	var event map[string]any
	if err := json.Unmarshal(entries[0], &event); err != nil {
		t.Fatal(err)
	}
	if event["kind"] != "triage" {
		t.Fatalf("stored trusted proposal instead of triage: %v", event["kind"])
	}
	if err := j.SubmitTriage(c, RoutingResult{Decision: "proposed"}); err == nil {
		t.Fatal("proposal was incorrectly stored as classifier-only triage")
	}
}
