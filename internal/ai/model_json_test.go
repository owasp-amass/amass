// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "testing"

func TestModelJSON(t *testing.T) {
	fence := codeFence
	for name, tc := range map[string]struct{ in, want string }{
		"bare":            {`{"a":1}`, `{"a":1}`},
		"padded":          {"  \n{\"a\":1}\n ", `{"a":1}`},
		"fence json tag":  {fence + "json\n{\"a\":1}\n" + fence, `{"a":1}`},
		"fence JSON tag":  {fence + "JSON\n{\"a\":1}\n" + fence, `{"a":1}`},
		"fence no tag":    {fence + "\n{\"a\":1}\n" + fence, `{"a":1}`},
		"fence one line":  {fence + "json{\"a\":1}" + fence, `{"a":1}`},
		"think then json": {"<think>\nlet me plan\n</think>\n{\"a\":1}", `{"a":1}`},
		"think then fence": {"<think>x</think>" + fence + "json\n{\"a\":1}\n" + fence,
			`{"a":1}`},
		"unclosed fence": {fence + "json\n{\"a\":1}", `{"a":1}`},
		// Prose is never stripped: strict decoding must still reject it.
		"prose before":   {"Here you go: {\"a\":1}", "Here you go: {\"a\":1}"},
		"unclosed think": {"<think>never ends {\"a\":1}", "<think>never ends {\"a\":1}"},
	} {
		if got := ModelJSON(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

func TestInferrerAcceptsFencedProposal(t *testing.T) {
	answer := codeFence + "json\n" + `{"subject_id":"a","predicate":"none","object_id":"b","confidence":0.1,"reason":"insufficient","evidence_ids":[],"contradictions":[]}` + "\n" + codeFence
	i := Inferrer{Model: inferenceModel{answer: answer}, MinSources: 2}
	p, err := i.Analyze(t.Context(), Candidate{SubjectID: "a", ObjectID: "b", AllowedLabels: []string{"subsidiary"}})
	if err != nil || p != nil {
		t.Fatalf("fenced 'none' proposal must parse and yield no proposal: p=%v err=%v", p, err)
	}
}
