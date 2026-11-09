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
	Runner   ai.ToolRunner
	Token    string
	mu       sync.Mutex
	sessions map[string]bool
}

func NewHTTPServer(runner ai.ToolRunner, token string) *HTTPServer {
	return &HTTPServer{Runner: runner, Token: token, sessions: map[string]bool{}}
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
		http.Error(w, "origin forbidden", 403)
		return
	}
	if s.Token == "" {
		http.Error(w, "server token not configured", 503)
		return
	}
	expected := "Bearer " + s.Token
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "SSE not offered; use POST", 405)
		return
	}
	if r.Method == http.MethodDelete {
		session := r.Header.Get("Mcp-Session-Id")
		s.mu.Lock()
		_, exists := s.sessions[session]
		if exists {
			delete(s.sessions, session)
		}
		s.mu.Unlock()
		if !exists {
			http.Error(w, "unknown MCP session", 404)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", 405)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "application/json required", 415)
		return
	}
	// Streamable HTTP clients must advertise JSON and SSE; this server
	// deliberately selects JSON responses for single-message POSTs.
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		http.Error(w, "Accept must include application/json and text/event-stream", 406)
		return
	}
	defer r.Body.Close()
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
			http.Error(w, "session initialization failed", 500)
			return
		}
		id := hex.EncodeToString(sessionBytes)
		s.mu.Lock()
		s.sessions[id] = false
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
	initialized, exists := s.sessions[session]
	s.mu.Unlock()
	if !exists {
		http.Error(w, "MCP session missing or expired", 404)
		return
	}
	if len(req.ID) == 0 {
		if req.Method == "notifications/initialized" {
			s.mu.Lock()
			s.sessions[session] = true
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
		for _, t := range ai.Specs() {
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Parameters})
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
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		result, err := s.Runner.Run(ctx, p.Name, p.Arguments)
		cancel()
		if err != nil {
			mcpJSON(w, 200, rpcResult(req.ID, map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": err.Error()}}}))
			return
		}
		mcpJSON(w, 200, rpcResult(req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": string(result)}}}))
	default:
		mcpJSON(w, 200, rpcError(req.ID, -32601, fmt.Sprintf("unsupported method: %s", req.Method)))
	}
}
func mcpJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
