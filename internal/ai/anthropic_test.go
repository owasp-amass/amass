// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
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
