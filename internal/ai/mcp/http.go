// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// HTTPServer serves bounded read-only MCP requests using the Streamable HTTP
// JSON response mode. Sessions are in memory and never authorize writes.
// Authentication is required even when Docker publishes only on loopback.
type HTTPServer struct {
	Runner ai.ToolRunner
	// Model is optional; see Server.
	Model    ai.Model
	Evidence *ai.EvidenceStore
	Token    string
	// SessionTTL is how long an idle session stays valid; MaxSessions caps
	// concurrent sessions (the least recently used is evicted first).
	SessionTTL  time.Duration
	MaxSessions int
	now         func() time.Time
	mu          sync.Mutex
	sessions    map[string]*mcpSession
}

type mcpSession struct {
	initialized bool
	lastSeen    time.Time
}

// Session defaults bound memory held for authenticated clients that never
// send DELETE.
const (
	DefaultSessionTTL  = 30 * time.Minute
	DefaultMaxSessions = 256
)

func NewHTTPServer(runner ai.ToolRunner, token string) *HTTPServer {
	return &HTTPServer{Runner: runner, Evidence: ai.NewEvidenceStore(), Token: token, SessionTTL: DefaultSessionTTL,
		MaxSessions: DefaultMaxSessions, now: time.Now, sessions: map[string]*mcpSession{}}
}

func (s *HTTPServer) clock() time.Time {
	if s.now != nil {
		return s.now()
	}

	return time.Now()
}

func (s *HTTPServer) ttl() time.Duration {
	if s.SessionTTL > 0 {
		return s.SessionTTL
	}

	return DefaultSessionTTL
}

// addSession registers id, first dropping expired sessions and, at the cap,
// the least recently used one. The caller holds s.mu.
func (s *HTTPServer) addSession(id string) {
	now := s.clock()
	for key, sess := range s.sessions {
		if now.Sub(sess.lastSeen) > s.ttl() {
			delete(s.sessions, key)
		}
	}

	limit := s.MaxSessions
	if limit < 1 {
		limit = DefaultMaxSessions
	}
	for len(s.sessions) >= limit {
		oldest := ""
		for key, sess := range s.sessions {
			if oldest == "" || sess.lastSeen.Before(s.sessions[oldest].lastSeen) {
				oldest = key
			}
		}

		delete(s.sessions, oldest)
	}

	s.sessions[id] = &mcpSession{lastSeen: now}
}

// touchSession returns the live session for id and refreshes its idle
// timer, or nil when it is unknown or expired. The caller holds s.mu.
func (s *HTTPServer) touchSession(id string) *mcpSession {
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}

	now := s.clock()
	if now.Sub(sess.lastSeen) > s.ttl() {
		delete(s.sessions, id)
		return nil
	}

	sess.lastSeen = now
	return sess
}

func (s *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		mcpJSON(w, 200, map[string]any{"status": "running", "component": "mcp-http"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.Token == "" || s.Runner.Graph == nil || s.Runner.Catalog == nil {
			mcpJSON(w, 503, map[string]any{"status": "unconfigured"})
			return
		}

		mcpJSON(w, 200, map[string]any{"status": "ready", "transport": "streamable-http", "access": "read_only"})
	})
	mux.HandleFunc("/mcp", s.handleMCP)
	return mux
}

func validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	o, err := url.Parse(origin)
	if err != nil || o.User != nil {
		return false
	}

	host := o.Hostname()
	// Browser-driven requests to a locally published port are allowed only
	// with matching origin and host; this prevents DNS-rebinding origins.
	target := r.Host
	if h, _, e := net.SplitHostPort(target); e == nil {
		target = h
	}

	return (host == "localhost" || host == "127.0.0.1" || host == "::1") &&
		(target == "localhost" || target == "127.0.0.1" || target == "::1")
}

func (s *HTTPServer) handleMCP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !validOrigin(r) {
		http.Error(w, "origin forbidden", http.StatusForbidden)
		return
	}
	if s.Token == "" {
		http.Error(w, "server token not configured", http.StatusServiceUnavailable)
		return
	}

	expected := "Bearer " + s.Token
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "SSE not offered; use POST", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodDelete {
		session := r.Header.Get("Mcp-Session-Id")
		s.mu.Lock()
		exists := s.touchSession(session) != nil
		if exists {
			delete(s.sessions, session)
		}

		s.mu.Unlock()
		if !exists {
			http.Error(w, "unknown MCP session", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return
	}

	// Streamable HTTP clients must advertise JSON and SSE; this server
	// deliberately selects JSON responses for single-message POSTs.
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		http.Error(w, "Accept must include application/json and text/event-stream", http.StatusNotAcceptable)
		return
	}

	defer func() { _ = r.Body.Close() }()
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	var req incoming
	if err := d.Decode(&req); err != nil {
		mcpJSON(w, 400, rpcError(nil, -32700, "parse error"))
		return
	}

	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		mcpJSON(w, 400, rpcError(nil, -32600, "invalid request body"))
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		mcpJSON(w, 400, rpcError(req.ID, -32600, "invalid JSON-RPC request"))
		return
	}
	if req.Method == "initialize" {
		if len(req.ID) == 0 {
			mcpJSON(w, 400, rpcError(nil, -32600, "initialize requires ID"))
			return
		}

		sessionBytes := make([]byte, 24)
		if _, err := rand.Read(sessionBytes); err != nil {
			http.Error(w, "session initialization failed", http.StatusInternalServerError)
			return
		}

		id := hex.EncodeToString(sessionBytes)
		s.mu.Lock()
		s.addSession(id)
		s.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
		mcpJSON(w, 200, rpcResult(req.ID, map[string]any{
			"protocolVersion": "2025-11-25",
			"serverInfo":      map[string]any{"name": "amass-ai", "version": "0.2.0"},
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		}))
		return
	}

	session := r.Header.Get("Mcp-Session-Id")
	s.mu.Lock()
	sess := s.touchSession(session)
	initialized := sess != nil && sess.initialized
	s.mu.Unlock()
	if sess == nil {
		http.Error(w, "MCP session missing or expired", http.StatusNotFound)
		return
	}
	if len(req.ID) == 0 {
		if req.Method == "notifications/initialized" {
			s.mu.Lock()
			if live := s.touchSession(session); live != nil {
				live.initialized = true
			}

			s.mu.Unlock()
		}

		w.WriteHeader(http.StatusAccepted)
		return
	}
	if !initialized && req.Method != "ping" {
		mcpJSON(w, 200, rpcError(req.ID, -32000, "MCP not initialized"))
		return
	}
	switch req.Method {
	case "ping":
		mcpJSON(w, 200, rpcResult(req.ID, map[string]any{}))
	case "tools/list":
		tools := make([]any, 0)
		for _, t := range toolSpecs(s.Runner) {
			tools = append(tools,
				map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Parameters})
		}

		mcpJSON(w, 200, rpcResult(req.ID, map[string]any{"tools": tools}))
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			mcpJSON(w, 200, rpcError(req.ID, -32602, "invalid tool request"))
			return
		}

		s.mu.Lock()
		if s.Evidence == nil {
			s.Evidence = ai.NewEvidenceStore()
		}

		store := s.Evidence
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), ai.ToolTimeout(p.Name))
		result, err := runTool(ctx, s.Runner, s.Model, store, p.Name, p.Arguments)
		cancel()
		if err != nil {
			mcpJSON(w, 200, rpcResult(req.ID,
				map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": err.Error()}}}))
			return
		}

		mcpJSON(w, 200, rpcResult(req.ID,
			map[string]any{"content": []any{map[string]any{"type": "text", "text": string(result)}}}))
	default:
		mcpJSON(w, 200, rpcError(req.ID, -32601, fmt.Sprintf("unsupported method: %s", req.Method)))
	}
}

func mcpJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
