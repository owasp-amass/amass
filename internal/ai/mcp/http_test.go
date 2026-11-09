// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

func post(t *testing.T, url, token, session, body string) (int, http.Header, map[string]any) {
	t.Helper()
	req, err := http.NewRequest("POST", url+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	// Authentication/session errors may intentionally be plain text.
	// Only successful JSON-RPC responses require a JSON envelope.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.StatusCode != 202 &&
		len(bytes.TrimSpace(raw)) > 0 && json.Unmarshal(raw, &result) != nil {
		t.Fatalf("invalid JSON success response: %s", raw)
	}
	if resp.StatusCode == 200 && len(bytes.TrimSpace(raw)) == 0 {
		t.Fatal("successful JSON-RPC request returned an empty body")
	}

	return resp.StatusCode, resp.Header, result
}

func TestHTTPMCPAuthenticatedSessionAndTools(t *testing.T) {
	token := strings.Repeat("x", 40)
	svc := NewHTTPServer(ai.ToolRunner{Limits: ai.DefaultLimits()}, token)
	server := httptest.NewServer(svc.Handler())
	defer server.Close()
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	if code, _, _ := post(t, server.URL, "", "", init); code != 401 {
		t.Fatalf("MCP accepted unauthenticated init: %d", code)
	}

	code, header, result := post(t, server.URL, token, "", init)
	session := header.Get("Mcp-Session-Id")
	if code != 200 || len(session) < 32 || result["result"] == nil {
		t.Fatalf("failed initialize: %d %s %+v", code, session, result)
	}
	if code, _, got := post(t, server.URL, token, session,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); code != 200 || got["error"] == nil {
		t.Fatalf("allowed tools before initialization: %+v", got)
	}
	if code, _, _ := post(t, server.URL, token, session,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != 202 {
		t.Fatalf("initialization notification: %d", code)
	}
	if code, _, got := post(t, server.URL, token, session,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`); code != 200 || got["result"] == nil {
		t.Fatalf("missing tools list after init: %d %+v", code, got)
	}

	req, err := http.NewRequest("DELETE", server.URL+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Mcp-Session-Id", session)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatalf("session deletion: %d", res.StatusCode)
	}
	if code, _, _ := post(t, server.URL, token, session, `{"jsonrpc":"2.0","id":4,"method":"ping"}`); code != 404 {
		t.Fatalf("deleted session accepted: %d", code)
	}
}

func TestHTTPMCPRejectsUntrustedBrowserOrigin(t *testing.T) {
	svc := NewHTTPServer(ai.ToolRunner{}, strings.Repeat("a", 40))
	server := httptest.NewServer(svc.Handler())
	defer server.Close()
	req, _ := http.NewRequest("POST", server.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Origin", "https://untrusted.invalid")
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 40))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("untrusted browser origin allowed: %d", resp.StatusCode)
	}
}

func TestHTTPMCPSessionsExpireAndAreCapped(t *testing.T) {
	token := strings.Repeat("y", 40)
	// The clock is read by server goroutines, so it is atomic for -race.
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC).UnixNano())
	advance := func(d time.Duration) { clock.Add(int64(d)) }
	svc := NewHTTPServer(ai.ToolRunner{Limits: ai.DefaultLimits()}, token)
	svc.SessionTTL = time.Minute
	svc.MaxSessions = 2
	svc.now = func() time.Time { return time.Unix(0, clock.Load()) }
	server := httptest.NewServer(svc.Handler())
	defer server.Close()
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	ping := `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	open := func() string {
		_, header, _ := post(t, server.URL, token, "", init)
		return header.Get("Mcp-Session-Id")
	}

	first := open()
	advance(30 * time.Second)
	if code, _, _ := post(t, server.URL, token, first, ping); code != 200 {
		t.Fatalf("live session rejected: %d", code)
	}

	advance(61 * time.Second)
	if code, _, _ := post(t, server.URL, token, first, ping); code != 404 {
		t.Fatalf("idle session must expire, got %d", code)
	}

	a := open()
	advance(time.Second)
	b := open()
	advance(time.Second)
	c := open()
	svc.mu.Lock()
	count := len(svc.sessions)
	svc.mu.Unlock()
	if count != 2 {
		t.Fatalf("session cap not enforced: %d sessions", count)
	}
	if code, _, _ := post(t, server.URL, token, a, ping); code != 404 {
		t.Fatalf("least recently used session must be evicted, got %d", code)
	}
	for _, id := range []string{b, c} {
		if code, _, _ := post(t, server.URL, token, id, ping); code != 200 {
			t.Fatalf("recent session %s rejected: %d", id, code)
		}
	}
}
