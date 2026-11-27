// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

// The defaults must leave room for one request, or every user would be told
// to change them; a growing prompt shows up here first.
func TestDocumentDefaultsFitTheContext(t *testing.T) {
	if need := documentRequestTokens(DefaultDocumentChunk, DefaultDocumentReplyTokens); need >
		DefaultDocumentContextTokens {
		t.Fatalf("a default request needs about %d tokens, more than the default context of %d", need,
			DefaultDocumentContextTokens)
	}
}

func TestDocumentContextWarnings(t *testing.T) {
	trained := `8192`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/show" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"model_info":{"general.architecture":"qwen3","qwen3.context_length":` + trained + `}}`))
	}))
	defer srv.Close()

	d := &config.DocumentModelSettings{Enabled: true, Provider: "ollama", Endpoint: srv.URL, Model: "small-model"}
	got := strings.Join(DocumentContextWarnings(context.Background(), d), "\n")
	for _, want := range []string{"context_tokens is 16384, but small-model was trained with 8192",
		"more than the 8192-token context"} {
		if !strings.Contains(got, want) {
			t.Errorf("warnings lack %q:\n%s", want, got)
		}
	}

	trained = `40960`
	if got := DocumentContextWarnings(context.Background(), d); len(got) != 0 {
		t.Errorf("a model with room gets warnings: %v", got)
	}

	// Only Ollama models are checked.
	if got := DocumentContextWarnings(context.Background(), &config.DocumentModelSettings{Enabled: true,
		Provider: "anthropic", Model: "m"}); len(got) != 0 {
		t.Errorf("a hosted model gets warnings: %v", got)
	}
}
