// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompatibleModelToolCalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("auth header missing")
		}

		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req["model"] != "test-model" {
			t.Error("incorrect model")
		}

		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","function":{"name":"get_asset","arguments":"{\"id\":\"a\"}"}}]}}]}`))
	}))
	defer server.Close()
	response, err := (CompatibleModel{
		Endpoint:  server.URL,
		ModelName: "test-model",
		APIKey:    "test-key",
	}).Generate(context.Background(), []Message{{Role: "user", Text: "hello"}},
		[]ToolSpec{{Name: "get_asset", Parameters: map[string]any{"type": "object"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Calls) != 1 || response.Calls[0].Name != "get_asset" {
		t.Fatalf("calls=%+v", response.Calls)
	}
}

func TestCompatibleModelHonorsConfiguredClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// A bounded delay simulates a slow model response. Request-context
		// cancellation is not guaranteed to be visible to the handler until
		// body reads or writes, so never wait indefinitely for it here.
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()
	client := &http.Client{Timeout: 50 * time.Millisecond}
	_, err := (CompatibleModel{Endpoint: server.URL, ModelName: "slow-test-model", Client: client}).
		Generate(context.Background(), []Message{{Role: "user", Text: "hello"}}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected configured HTTP timeout, got %v", err)
	}
}

const compatibleOK = `{"choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}]}`

// A reasoning model that refuses max_tokens and temperature (as OpenAI's do)
// is asked again with max_completion_tokens and no temperature, and later
// requests are sent that way from the start.
func TestCompatibleModelAdaptsToRefusedFields(t *testing.T) {
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		bodies = append(bodies, req)
		if _, ok := req["max_tokens"]; ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"Unsupported parameter: 'max_tokens' is not supported ` +
				`with this model. Use 'max_completion_tokens' instead.","type":"invalid_request_error",` +
				`"param":"max_tokens"}}`))
			return
		}
		if _, ok := req["temperature"]; ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"Unsupported value: 'temperature' does not support 0 ` +
				`with this model. Only the default (1) value is supported.","type":"invalid_request_error"}}`))
			return
		}
		_, _ = w.Write([]byte(compatibleOK))
	}))
	defer server.Close()

	zero := 0.0
	m := NewCompatibleModel(server.URL, "reasoning-model", "k", nil)
	m.MaxTokens, m.Temperature = 4096, &zero
	for range 2 {
		if _, err := m.Generate(context.Background(), []Message{{Role: "user", Text: "q"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 4 {
		t.Fatalf("requests = %d, want 3 for the first reply and 1 for the second", len(bodies))
	}
	last := bodies[3]
	if last["max_completion_tokens"] != float64(4096) || last["max_tokens"] != nil || last["temperature"] != nil {
		t.Errorf("later request = %+v", last)
	}
}

// A JSON schema is sent as the response format; a server that refuses it is
// asked again with the prompt alone.
func TestCompatibleModelStructured(t *testing.T) {
	var formats []any
	refuse := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		formats = append(formats, req["response_format"])
		if refuse && req["response_format"] != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"response_format json_schema is not supported"}`))
			return
		}
		_, _ = w.Write([]byte(compatibleOK))
	}))
	defer server.Close()

	schema := JSONSchema{Name: "document findings", Schema: map[string]any{"type": "object"}}
	m := NewCompatibleModel(server.URL, "m", "", nil)
	if got, err := m.GenerateStructured(context.Background(), []Message{{Role: "user", Text: "q"}}, schema); err != nil ||
		got.Text != `{"ok":true}` {
		t.Fatalf("GenerateStructured = %+v, %v", got, err)
	}
	f, _ := formats[0].(map[string]any)
	js, _ := f["json_schema"].(map[string]any)
	if f["type"] != "json_schema" || js["name"] != "document_findings" {
		t.Errorf("response_format = %+v", formats[0])
	}

	refuse, formats = true, nil
	m = NewCompatibleModel(server.URL, "m", "", nil)
	if _, err := m.GenerateStructured(context.Background(), []Message{{Role: "user", Text: "q"}}, schema); err != nil {
		t.Fatal(err)
	}
	if len(formats) != 2 || formats[1] != nil {
		t.Errorf("formats = %+v, want the schema then none", formats)
	}
}

// A refused request reports the provider's reason, and a reply cut off at
// the token cap is ErrReplyLength.
func TestCompatibleModelErrors(t *testing.T) {
	reply := `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}`
	status := http.StatusUnauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	defer server.Close()

	m := NewCompatibleModel(server.URL, "m", "secret", nil)
	_, err := m.Generate(context.Background(), []Message{{Role: "user", Text: "q"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "401: invalid_request_error: Incorrect API key provided") ||
		strings.Contains(err.Error(), "secret") {
		t.Fatalf("error = %v", err)
	}

	status, reply = http.StatusOK, `{"choices":[{"message":{"content":"{\"part"},"finish_reason":"length"}]}`
	if _, err := m.Generate(context.Background(), []Message{{Role: "user", Text: "q"}}, nil); !errors.Is(err,
		ErrReplyLength) {
		t.Fatalf("error = %v, want ErrReplyLength", err)
	}
}
