// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	got, err := (AnthropicModel{
		Endpoint:  s.URL,
		ModelName: "some-model",
		APIKey:    "test-secret",
	}).Generate(context.Background(), []Message{{Role: "user", Text: "lookup a"}}, Specs())
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
	if _, err := (AnthropicModel{
		Endpoint:    s.URL,
		ModelName:   "m",
		APIKey:      "k",
		Temperature: &zero,
	}).Generate(context.Background(), history, nil); err != nil {
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
	if _, err := (AnthropicModel{
		Endpoint:           s.URL,
		ModelName:          "m",
		APIKey:             "k",
		MaxTokens:          512,
		DisablePromptCache: true,
	}).Generate(context.Background(), history, nil); err != nil {
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
	if _, err := (AnthropicModel{
		Endpoint:  s.URL,
		ModelName: "m",
		APIKey:    "k",
	}).Generate(context.Background(), []Message{{Role: "user", Text: "q"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, set := body["system"]; set {
		t.Fatal("an empty system prompt must be omitted")
	}
}

// A refused request reports the reason the API gave, never the key.
func TestAnthropicErrorReason(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
	}))
	defer s.Close()

	_, err := (AnthropicModel{Endpoint: s.URL, ModelName: "some-model", APIKey: "test-secret"}).Generate(
		context.Background(), []Message{{Role: "user", Text: "hi"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "401: authentication_error: invalid x-api-key") {
		t.Fatalf("error = %v, want the API's reason", err)
	}
	if strings.Contains(err.Error(), "test-secret") {
		t.Error("the error shows the API key")
	}
}

// A model that rejects the temperature field is asked again without it, and
// later requests leave it out.
func TestAnthropicDropsARejectedTemperature(t *testing.T) {
	var withTemp, without int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["temperature"]; ok {
			withTemp++
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error",` +
				`"message":"` + "`temperature`" + ` is deprecated for this model."}}`))
			return
		}
		without++
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer s.Close()

	zero := 0.0
	m := NewAnthropicModel(s.URL, "some-model", "k", nil)
	m.Temperature = &zero
	for range 2 {
		got, err := m.Generate(context.Background(), []Message{{Role: "user", Text: "hi"}}, nil)
		if err != nil || got.Text != "ok" {
			t.Fatalf("Generate = %+v, %v", got, err)
		}
	}
	if withTemp != 1 || without != 2 {
		t.Errorf("requests with temperature %d, without %d; want 1 and 2", withTemp, without)
	}
}

// A model that refuses a forced tool choice is offered the tool unforced,
// once and from then on, and its tool call or its text is the structured
// reply.
func TestAnthropicStructuredWithoutForcedTool(t *testing.T) {
	var forced, unforced int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["tool_choice"]; ok {
			forced++
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error",` +
				`"message":"tool_choice: type \"tool\" and \"any\" are not supported for this model."}}`))
			return
		}
		unforced++
		if unforced == 1 {
			_, _ = w.Write([]byte(`{"content":[{"type":"tool_use","id":"t1","name":"answer","input":{"kind":"person"}}],` +
				`"usage":{"input_tokens":1,"output_tokens":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"kind\":\"organization\"}"}],` +
			`"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer s.Close()

	m := NewAnthropicModel(s.URL, "some-model", "k", nil)
	schema := JSONSchema{Name: "answer", Schema: map[string]any{"type": "object"}}
	got, err := m.GenerateStructured(context.Background(), []Message{{Role: "user", Text: "q"}}, schema)
	if err != nil || !strings.Contains(got.Text, "person") {
		t.Fatalf("tool call reply = %+v, %v", got, err)
	}
	got, err = m.GenerateStructured(context.Background(), []Message{{Role: "user", Text: "q"}}, schema)
	if err != nil || !strings.Contains(got.Text, "organization") {
		t.Fatalf("text reply = %+v, %v", got, err)
	}
	if forced != 1 || unforced != 2 {
		t.Errorf("forced requests %d, unforced %d; want 1 and 2", forced, unforced)
	}
}
