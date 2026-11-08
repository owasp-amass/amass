// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
	response, err := (CompatibleModel{Endpoint: server.URL, ModelName: "test-model", APIKey: "test-key"}).Generate(context.Background(), []Message{{Role: "user", Text: "hello"}}, Specs())
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Calls) != 1 || response.Calls[0].Name != "get_asset" {
		t.Fatalf("calls=%+v", response.Calls)
	}
}
