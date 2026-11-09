// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	response, err := (CompatibleModel{Endpoint: server.URL, ModelName: "test-model", APIKey: "test-key"}).Generate(context.Background(), []Message{{Role: "user", Text: "hello"}}, Specs())
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
