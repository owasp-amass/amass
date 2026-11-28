// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"strings"
	"testing"
)

func TestMaskedHidesSecretsFromModels(t *testing.T) {
	token := "ghp_" + strings.Repeat("Q7mZ2pX9vB4kL8nR3tW6yC1dF5gH0jS", 2)[:36]
	history := []Message{
		{Role: "system", Text: "answer from the evidence"},
		{Role: "tool", ToolCallID: "c1", Text: "the page at https://www.example.com/app.js holds " + token},
	}

	got := Masked(history)
	if strings.Contains(got[1].Text, token) || !strings.Contains(got[1].Text, "[github_token ") {
		t.Errorf("tool result was not masked: %q", got[1].Text)
	}
	if got[1].ToolCallID != "c1" || got[0].Text != history[0].Text {
		t.Errorf("Masked changed more than the secret: %+v", got)
	}
	if !strings.Contains(history[1].Text, token) {
		t.Error("Masked changed the caller's history")
	}

	clean := []Message{{Role: "user", Text: "which domains does OWASP own?"}}
	if out := Masked(clean); &out[0] != &clean[0] {
		t.Error("history without secrets was copied")
	}
}
