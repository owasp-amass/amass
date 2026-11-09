// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type ollamaStub struct {
	mu       sync.Mutex
	requests []map[string]any
	reply    func(req map[string]any) (int, string)
}

func (s *ollamaStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}

		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}

		s.mu.Lock()
		s.requests = append(s.requests, req)
		s.mu.Unlock()
		code, body := s.reply(req)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOllamaRequestShapeAndToolCalls(t *testing.T) {
	stub := &ollamaStub{reply: func(map[string]any) (int, string) {
		return 200, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"get_asset","arguments":{"id":"a"}}}]},"done":true,"done_reason":"stop","prompt_eval_count":11,"eval_count":7}`
	}}
	srv := stub.server(t)
	m := NewOllamaModel(srv.URL, "qwen3:8b", nil)
	history := []Message{
		{Role: "system", Text: "sys"},
		{Role: "user", Text: "q"},
		{
			Role:  "assistant",
			Calls: []Call{{ID: "c1", Name: "find_assets", Arguments: json.RawMessage(`{"type":"FQDN"}`)}},
		},
		{Role: "tool", ToolCallID: "c1", Text: "[]"},
	}
	got, err := m.Generate(context.Background(), history, Specs()[:1])
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Calls) != 1 || got.Calls[0].Name != "get_asset" || string(got.Calls[0].Arguments) != `{"id":"a"}` ||
		got.Calls[0].ID == "" {
		t.Fatalf("tool call not decoded: %+v", got.Calls)
	}
	if got.InputTokens != 11 || got.OutputTokens != 7 {
		t.Fatalf("token counts: %+v", got)
	}

	req := stub.requests[0]
	if req["think"] != false || req["stream"] != false || req["keep_alive"] != DefaultOllamaKeepAlive {
		t.Fatalf("think/stream/keep_alive: %v %v %v", req["think"], req["stream"], req["keep_alive"])
	}

	opts, _ := req["options"].(map[string]any)
	if opts["num_ctx"] != float64(DefaultOllamaContextTokens) {
		t.Fatalf("num_ctx: %v", opts)
	}
	if _, set := opts["temperature"]; set {
		t.Fatal("temperature must be omitted when unset")
	}

	msgs, _ := req["messages"].([]any)
	tool, _ := msgs[3].(map[string]any)
	if tool["role"] != "tool" || tool["tool_name"] != "find_assets" {
		t.Fatalf("tool result must name its call: %v", tool)
	}

	assistant, _ := msgs[2].(map[string]any)
	calls, _ := assistant["tool_calls"].([]any)
	fn, _ := calls[0].(map[string]any)["function"].(map[string]any)
	if args, ok := fn["arguments"].(map[string]any); !ok || args["type"] != "FQDN" {
		t.Fatalf("assistant tool call arguments must be a JSON object: %v", fn)
	}
	if tools, _ := req["tools"].([]any); len(tools) != 1 {
		t.Fatalf("tools not sent: %v", req["tools"])
	}
}

func TestOllamaStructuredAndOptions(t *testing.T) {
	stub := &ollamaStub{reply: func(map[string]any) (int, string) {
		return 200, `{"message":{"role":"assistant","content":"{\"ok\":true}"},"done":true,"done_reason":"stop"}`
	}}
	srv := stub.server(t)
	temp := 0.0
	m := NewOllamaModel(srv.URL+"/api/chat", "qwen3:8b", nil)
	m.Think, m.ContextTokens, m.MaxTokens, m.Temperature, m.KeepAlive = true, 4096, 512, &temp, "5m"
	schema := JSONSchema{Name: "x", Schema: map[string]any{"type": "object"}}
	got, err := m.GenerateStructured(context.Background(), []Message{{Role: "user", Text: "q"}}, schema)
	if err != nil || got.Text != `{"ok":true}` {
		t.Fatalf("structured reply: %+v err=%v", got, err)
	}

	req := stub.requests[0]
	opts, _ := req["options"].(map[string]any)
	if req["think"] != true || req["keep_alive"] != "5m" || opts["num_ctx"] != 4096.0 ||
		opts["num_predict"] != 512.0 || opts["temperature"] != 0.0 {
		t.Fatalf("options not applied: %v", req)
	}
	if format, _ := req["format"].(map[string]any); format["type"] != "object" {
		t.Fatalf("schema not sent as format: %v", req["format"])
	}
}

func TestOllamaRetriesWithoutThinkForNonReasoningModels(t *testing.T) {
	stub := &ollamaStub{reply: func(req map[string]any) (int, string) {
		if _, set := req["think"]; set {
			return 400, `{"error":"\"llama3\" does not support thinking"}`
		}

		return 200, `{"message":{"role":"assistant","content":"READY"},"done":true,"done_reason":"stop"}`
	}}
	srv := stub.server(t)
	m := NewOllamaModel(srv.URL, "llama3", nil)
	for i := 0; i < 2; i++ {
		if got, err := m.Generate(context.Background(), []Message{{Role: "user", Text: "q"}},
			nil); err != nil || got.Text != "READY" {
			t.Fatalf("call %d: %+v err=%v", i, got, err)
		}
	}
	// First call: rejected then retried. Second call: think already omitted.
	if len(stub.requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(stub.requests))
	}
	if _, set := stub.requests[2]["think"]; set {
		t.Fatal("think must stay omitted after a model rejects it")
	}
}

func TestOllamaErrorsAndEndpoint(t *testing.T) {
	stub := &ollamaStub{reply: func(map[string]any) (int, string) {
		return 200, `{"message":{"role":"assistant","content":"partial"},"done":true,"done_reason":"length"}`
	}}
	srv := stub.server(t)
	if _, err := NewOllamaModel(srv.URL, "m",
		nil).Generate(context.Background(), []Message{{Role: "user", Text: "q"}},
		nil); err == nil || !strings.Contains(err.Error(), "token limit") {
		t.Fatalf("truncated reply must fail: %v", err)
	}

	stub.reply = func(map[string]any) (int, string) {
		return 404, `{"error":"model \"nope\" not found, try pulling it first"}`
	}
	if _, err := NewOllamaModel(srv.URL, "nope",
		nil).Generate(context.Background(), []Message{{Role: "user", Text: "q"}},
		nil); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error body must be surfaced: %v", err)
	}
	for in, want := range map[string]string{
		"http://ollama:11434":           "http://ollama:11434/api/chat",
		"http://ollama:11434/":          "http://ollama:11434/api/chat",
		"http://ollama:11434/api/chat":  "http://ollama:11434/api/chat",
		"https://llm.example/ollama///": "https://llm.example/ollama/api/chat",
	} {
		if got, err := OllamaChatURL(in); err != nil || got != want {
			t.Errorf("%s: got %s err=%v", in, got, err)
		}
	}
	if _, err := OllamaChatURL("http://ollama:11434/v1/chat/completions"); err == nil {
		t.Error("OpenAI-compatible URL must be rejected for the native provider")
	}
}

func TestAnthropicStructuredForcesTool(t *testing.T) {
	var body map[string]any
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"content":[{"type":"tool_use","id":"t1","name":"investigation_goal","input":{"purpose":"connected"}}],"usage":{"input_tokens":5,"output_tokens":3}}`))
	}))
	defer s.Close()
	m := AnthropicModel{Endpoint: s.URL, ModelName: "m", APIKey: "k"}
	got, err := m.GenerateStructured(context.Background(), []Message{{Role: "user", Text: "q"}},
		JSONSchema{Name: "investigation_goal", Schema: map[string]any{"type": "object"}})
	if err != nil || got.Text != `{"purpose":"connected"}` || got.InputTokens != 5 {
		t.Fatalf("structured reply: %+v err=%v", got, err)
	}

	choice, _ := body["tool_choice"].(map[string]any)
	if choice["type"] != "tool" || choice["name"] != "investigation_goal" {
		t.Fatalf("tool_choice must force the schema tool: %v", body["tool_choice"])
	}
}

func TestGoalSchemaEnumeratesCatalogAndMetersUsage(t *testing.T) {
	schema := goalJSONSchema(testOAMCatalog.Relations(), testOAMCatalog.SearchFields())
	props := schema.Schema["properties"].(map[string]any)
	allowed := props["relationships"].(map[string]any)["items"].(map[string]any)["enum"].([]any)
	if len(allowed) != len(testOAMCatalog) {
		t.Fatalf("each catalog transition must be one allowed value: %v", allowed)
	}
	for i, want := range testOAMCatalog {
		got := allowed[i].(map[string]any)
		if got["source_type"] != want.SourceType || got["label"] != want.Label ||
			got["relation_type"] != want.RelationType || got["destination_type"] != want.DestinationType {
			t.Fatalf("transition %d: got %v want %+v", i, got, want)
		}
	}

	// The planner uses structured generation; metering wraps it and counts usage.
	model := &structuredRecorder{
		reply: `{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["URL"],"direction":"both","purpose":"connected","relationships":[],"path_rule":""}`,
	}
	agent := Agent{Model: model, Runner: ToolRunner{Limits: DefaultLimits(), Catalog: testOAMCatalog}}
	agent, meter := agent.metered()
	q, err := agent.CompileQuestion(context.Background(), "Tell me about the URLs near tech.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if q.Source != SourceModelGoal || model.structured != 1 || model.plain != 0 {
		t.Fatalf("planner must use structured generation: %+v %+v", q, model)
	}
	if u := meter.snapshot(); u.Calls != 1 || u.InputTokens != 100 || u.OutputTokens != 20 {
		t.Fatalf("usage not metered: %+v", u)
	}
}

type structuredRecorder struct {
	reply             string
	structured, plain int
}

func (m *structuredRecorder) Generate(context.Context, []Message, []ToolSpec) (Response, error) {
	m.plain++
	return Response{Text: m.reply}, nil
}

func (m *structuredRecorder) GenerateStructured(_ context.Context, _ []Message, s JSONSchema) (Response, error) {
	m.structured++
	if s.Name != "investigation_goal" {
		return Response{}, nil
	}

	return Response{Text: m.reply, InputTokens: 100, OutputTokens: 20}, nil
}

func TestOllamaStructuredFallsBackWhenSchemaIsRejected(t *testing.T) {
	stub := &ollamaStub{reply: func(req map[string]any) (int, string) {
		if _, set := req["format"]; set {
			return 400, `{"error":"invalid JSON schema in format"}`
		}

		return 200, `{"message":{"role":"assistant","content":"{}"},"done":true,"done_reason":"stop"}`
	}}
	srv := stub.server(t)
	got, err := NewOllamaModel(srv.URL, "m", nil).GenerateStructured(context.Background(),
		[]Message{{Role: "user", Text: "q"}}, JSONSchema{Name: "x", Schema: map[string]any{"type": "object"}})
	if err != nil || got.Text != "{}" || len(stub.requests) != 2 {
		t.Fatalf("expected an unconstrained retry: %+v err=%v requests=%d", got, err, len(stub.requests))
	}
}
