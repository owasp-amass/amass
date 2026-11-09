// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnthropicToolCalling(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-secret" {
			t.Error("missing api key")
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"tool_use","id":"use1","name":"get_asset","input":{"id":"a"}}],"usage":{"input_tokens":10,"output_tokens":6}}`))
	}))
	defer s.Close()
	got, err := (AnthropicModel{Endpoint: s.URL, ModelName: "some-model", APIKey: "test-secret"}).Generate(context.Background(), []Message{{Role: "user", Text: "lookup a"}}, Specs())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Calls) != 1 || got.Calls[0].Name != "get_asset" {
		t.Fatalf("incorrect tool use: %+v", got)
	}
}

func TestAnthropicRequestShape(t *testing.T) {
	var body map[string]any
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer s.Close()
	zero := 0.0
	history := []Message{{Role: "system", Text: "catalog"}, {Role: "user", Text: "q"}}
	if _, err := (AnthropicModel{Endpoint: s.URL, ModelName: "m", APIKey: "k", Temperature: &zero}).Generate(context.Background(), history, nil); err != nil {
		t.Fatal(err)
	}
	if body["max_tokens"] != float64(DefaultAnthropicMaxTokens) || body["temperature"] != 0.0 {
		t.Fatalf("unexpected limits: max_tokens=%v temperature=%v", body["max_tokens"], body["temperature"])
	}
	system, _ := body["system"].([]any)
	if len(system) != 1 {
		t.Fatalf("system must be one text block, got %#v", body["system"])
	}
	block, _ := system[0].(map[string]any)
	cache, _ := block["cache_control"].(map[string]any)
	if block["text"] != "catalog" || cache["type"] != "ephemeral" {
		t.Fatalf("system block must carry the prompt and ephemeral cache_control: %#v", block)
	}

	body = nil
	if _, err := (AnthropicModel{Endpoint: s.URL, ModelName: "m", APIKey: "k", MaxTokens: 512, DisablePromptCache: true}).Generate(context.Background(), history, nil); err != nil {
		t.Fatal(err)
	}
	block, _ = body["system"].([]any)[0].(map[string]any)
	if _, cached := block["cache_control"]; cached || body["max_tokens"] != 512.0 {
		t.Fatalf("cache must be disabled and max_tokens honoured: %#v", body)
	}
	if _, set := body["temperature"]; set {
		t.Fatal("temperature must be omitted when unset")
	}

	body = nil
	if _, err := (AnthropicModel{Endpoint: s.URL, ModelName: "m", APIKey: "k"}).Generate(context.Background(), []Message{{Role: "user", Text: "q"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, set := body["system"]; set {
		t.Fatal("an empty system prompt must be omitted")
	}
}
