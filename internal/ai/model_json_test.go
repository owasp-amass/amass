// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/ai/review"
)

func TestInferrerAcceptsFencedProposal(t *testing.T) {
	answer := llm.CodeFence + "json\n" +
		`{"subject_id":"a","predicate":"none","object_id":"b","confidence":0.1,"reason":"insufficient","evidence_ids":[],"contradictions":[]}` + "\n" + llm.CodeFence
	i := Inferrer{Model: inferenceModel{answer: answer}, MinSources: 2}
	p, err := i.Analyze(t.Context(), review.Candidate{SubjectID: "a", ObjectID: "b", AllowedLabels: []string{"subsidiary"}})
	if err != nil || p != nil {
		t.Fatalf("fenced 'none' proposal must parse and yield no proposal: p=%v err=%v", p, err)
	}
}
