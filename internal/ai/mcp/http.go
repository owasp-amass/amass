// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
)

// HTTPServer serves read-only MCP over Streamable HTTP (JSON responses)
// with the MCP Go SDK, behind Amass's checks: a bearer token is required
// even when Docker publishes only on loopback, browser origins must be
// local, request bodies are bounded, and sessions expire when idle and are
// capped. Sessions are in memory and never authorize writes.
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
	once        sync.Once
	sdk         http.Handler
}

type mcpSession struct {
	lastSeen time.Time
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
// the least recently used one, and returns the dropped IDs. The caller holds
// s.mu.
func (s *HTTPServer) addSession(id string) []string {
	var dropped []string
	now := s.clock()
	for key, sess := range s.sessions {
		if now.Sub(sess.lastSeen) > s.ttl() {
			delete(s.sessions, key)
			dropped = append(dropped, key)
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
		dropped = append(dropped, oldest)
	}

	s.sessions[id] = &mcpSession{lastSeen: now}
	return dropped
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
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		// JSON responses only: no server-sent event stream is offered.
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "use POST or DELETE", http.StatusMethodNotAllowed)
		return
	}

	// Only sessions this server admitted reach the SDK, so expiry and the
	// session cap hold even though the SDK keeps its own session table.
	session := r.Header.Get("Mcp-Session-Id")
	if session != "" {
		s.mu.Lock()
		live := s.touchSession(session) != nil
		if live && r.Method == http.MethodDelete {
			delete(s.sessions, session)
		}

		s.mu.Unlock()
		if !live {
			s.closeSDKSession(session)
			http.Error(w, "MCP session missing or expired", http.StatusNotFound)
			return
		}
	} else if r.Method == http.MethodDelete {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if session != "" {
		s.sdkHandler().ServeHTTP(w, r)
		return
	}

	// A request without a session can only be initialize; admit the session
	// the SDK creates, evicting the least recently used one at the cap.
	rec := &sessionRecorder{ResponseWriter: w}
	s.sdkHandler().ServeHTTP(rec, r)
	if id := rec.Header().Get("Mcp-Session-Id"); id != "" && rec.status < 300 {
		s.mu.Lock()
		evicted := s.addSession(id)
		s.mu.Unlock()
		for _, old := range evicted {
			s.closeSDKSession(old)
		}
	}
}

// sdkHandler returns the SDK's Streamable HTTP handler, built once.
func (s *HTTPServer) sdkHandler() http.Handler {
	s.once.Do(func() {
		s.mu.Lock()
		if s.Evidence == nil {
			s.Evidence = ai.NewEvidenceStore()
		}

		store := s.Evidence
		s.mu.Unlock()
		server := newSDKServer(s.Runner, s.Model, store)
		s.sdk = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
			&mcp.StreamableHTTPOptions{JSONResponse: true, SessionTimeout: s.ttl()})
	})

	return s.sdk
}

// closeSDKSession ends a session in the SDK after Amass expires or evicts it.
func (s *HTTPServer) closeSDKSession(id string) {
	if id == "" {
		return
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, "/mcp", nil)
	if err != nil {
		return
	}

	req.Header.Set("Mcp-Session-Id", id)
	s.sdkHandler().ServeHTTP(discardResponse{header: http.Header{}}, req)
}

// sessionRecorder notes the status the SDK writes.
type sessionRecorder struct {
	http.ResponseWriter
	status int
}

func (r *sessionRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *sessionRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}

	return r.ResponseWriter.Write(b)
}

func (r *sessionRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// discardResponse is a ResponseWriter for internal requests.
type discardResponse struct{ header http.Header }

func (d discardResponse) Header() http.Header { return d.header }

func (d discardResponse) Write(b []byte) (int, error) { return len(b), nil }

func (d discardResponse) WriteHeader(int) {}

func mcpJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
