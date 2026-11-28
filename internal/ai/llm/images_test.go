// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A user message's pictures reach each provider in its own form.
func TestMessagesCarryImages(t *testing.T) {
	page := Image{MediaType: "image/jpeg", Data: []byte{0xFF, 0xD8, 0xFF, 0xD9}}
	b64 := base64.StdEncoding.EncodeToString(page.Data)
	history := []Message{{Role: "user", Text: "read it", Images: []Image{page}}}

	capture := func(reply string) (*httptest.Server, *map[string]any) {
		body := map[string]any{}
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(reply))
		}))
		t.Cleanup(s.Close)
		return s, &body
	}
	firstMessage := func(body map[string]any) map[string]any {
		msgs, _ := body["messages"].([]any)
		if len(msgs) == 0 {
			t.Fatalf("no messages in %v", body)
		}
		m, _ := msgs[0].(map[string]any)
		return m
	}

	s, body := capture(`{"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)
	if _, err := (AnthropicModel{Endpoint: s.URL, ModelName: "m", APIKey: "k"}).Generate(context.Background(),
		history, nil); err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(firstMessage(*body)["content"]); !strings.Contains(string(raw), `"type":"image"`) ||
		!strings.Contains(string(raw), b64) {
		t.Errorf("anthropic content %s", raw)
	}

	s, body = capture(`{"message":{"role":"assistant","content":"ok"},"done":true}`)
	if _, err := NewOllamaModel(s.URL, "qwen3-vl", nil).Generate(context.Background(), history, nil); err != nil {
		t.Fatal(err)
	}
	if imgs, _ := firstMessage(*body)["images"].([]any); len(imgs) != 1 || imgs[0] != b64 {
		t.Errorf("ollama images %v", firstMessage(*body)["images"])
	}

	s, body = capture(`{"choices":[{"message":{"content":"ok"}}]}`)
	if _, err := (CompatibleModel{Endpoint: s.URL, ModelName: "m", APIKey: "k"}).Generate(context.Background(),
		history, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(firstMessage(*body)["content"])
	if !strings.Contains(string(raw), "data:image/jpeg;base64,"+b64) {
		t.Errorf("compatible content %s", raw)
	}
}

// Ollama's /api/show capabilities say whether a model sees pictures.
func TestOllamaCapable(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"capabilities":["completion","vision"],"model_info":{"x.context_length":8192}}`))
	}))
	defer s.Close()

	m := NewOllamaModel(s.URL, "qwen3-vl", nil)
	if ok, err := m.Capable(context.Background(), "vision"); err != nil || !ok {
		t.Errorf("vision = %v, %v", ok, err)
	}
	if ok, _ := m.Capable(context.Background(), "tools"); ok {
		t.Error("a capability Ollama does not list was reported")
	}
	if n, err := m.ContextLength(context.Background()); err != nil || n != 8192 {
		t.Errorf("context length = %d, %v", n, err)
	}
}
