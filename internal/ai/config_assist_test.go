// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// cfgModel returns a canned reply, standing in for a provider.
type cfgModel struct{ text string }

func (m cfgModel) Generate(context.Context, []llm.Message, []llm.ToolSpec) (llm.Response, error) {
	return llm.Response{Text: m.text}, nil
}

func TestSuggestConfig(t *testing.T) {
	reply := `{"summary":"scan owasp.org passively","rationale":"passive only",` +
		`"content":"seed:\n  domains:\n    - owasp.org\nscope:\n  ports:\n    - 443\n"}`

	edit, err := SuggestConfig(context.Background(), cfgModel{text: reply}, "", "set up a passive scan of owasp.org")
	if err != nil {
		t.Fatalf("SuggestConfig failed: %v", err)
	}
	if edit.Summary == "" || !strings.Contains(edit.Content, "owasp.org") {
		t.Errorf("unexpected proposal: %+v", edit)
	}
}

func TestSuggestConfigRefusesSecrets(t *testing.T) {
	reply := `{"summary":"add a key","content":"datasources:\n  - name: Shodan\n    creds:\n` +
		`      account:\n        apikey: LEAKED\n"}`

	if _, err := SuggestConfig(context.Background(), cfgModel{text: reply}, "", "add my shodan key"); err == nil {
		t.Error("SuggestConfig accepted a configuration that sets credentials")
	}
}

func TestSuggestConfigGuards(t *testing.T) {
	if _, err := SuggestConfig(context.Background(), nil, "", "anything"); err == nil {
		t.Error("a nil model was accepted")
	}
	if _, err := SuggestConfig(context.Background(), cfgModel{text: "{}"}, "", "  "); err == nil {
		t.Error("an empty request was accepted")
	}

	// An empty configuration is rejected rather than written.
	if _, err := SuggestConfig(context.Background(), cfgModel{text: `{"summary":"x","content":""}`},
		"", "do something"); err == nil {
		t.Error("an empty configuration was accepted")
	}
}
