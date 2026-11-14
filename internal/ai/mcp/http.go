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
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// HTTPServer serves MCP over Streamable HTTP with the MCP Go SDK, behind
// Amass's checks: a bearer token is required even when Docker publishes only
// on loopback, browser origins must be local, request bodies are bounded,
// and sessions expire when idle and are capped. Clients presenting Token get
// the read-only tools (JSON responses); clients presenting OperatorToken,
// when an Operator is configured, also get the operator tools, served with
// event streams so the server can ask the user to approve an action.
type HTTPServer struct {
	Runner ai.ToolRunner
	// Model is optional; see Server.
	Model    llm.Model
	Evidence *ai.EvidenceStore
	Token    string
	// OperatorToken and Operator enable operator mode; see Operator.
	OperatorToken string
	Operator      *Operator
	// SessionTTL is how long an idle session stays valid; MaxSessions caps
	// concurrent sessions (the least recently used is evicted first).
	SessionTTL  time.Duration
	MaxSessions int
	now         func() time.Time
	mu          sync.Mutex
	sessions    map[string]*mcpSession
	once        sync.Once
	sdk         http.Handler
	sdkOperator http.Handler
}

type mcpSession struct {
	lastSeen time.Time
	operator bool
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
func (s *HTTPServer) addSession(id string, operator bool) []string {
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

	s.sessions[id] = &mcpSession{lastSeen: now, operator: operator}
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

		mcpJSON(w, 200, map[string]any{"status": "ready", "transport": "streamable-http", "access": "read_only",
			"operator": s.Operator != nil && len(s.OperatorToken) >= 32})
	})
	mux.HandleFunc("/mcp", s.handleMCP)
	if s.Operator != nil && s.Operator.KeyLinks != nil {
		mux.Handle(keyLinkPrefix, s.Operator.KeyLinks)
	}
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

	got := []byte(r.Header.Get("Authorization"))
	reader := subtle.ConstantTimeCompare(got, []byte("Bearer "+s.Token)) == 1
	operator := s.Operator != nil && len(s.OperatorToken) >= 32 &&
		subtle.ConstantTimeCompare(got, []byte("Bearer "+s.OperatorToken)) == 1
	if !reader && !operator {
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
		sess := s.touchSession(session)
		// A session belongs to the token that opened it.
		live := sess != nil && sess.operator == operator
		if live && r.Method == http.MethodDelete {
			delete(s.sessions, session)
		}

		s.mu.Unlock()
		if !live {
			if sess == nil {
				s.closeSDKSession(session)
			}
			http.Error(w, "MCP session missing or expired", http.StatusNotFound)
			return
		}
	} else if r.Method == http.MethodDelete {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	handler := s.sdkHandler(operator)
	if session != "" {
		handler.ServeHTTP(w, r)
		return
	}

	// A request without a session can only be initialize; admit the session
	// the SDK creates, evicting the least recently used one at the cap.
	// The session is admitted as its headers go out, before the client can
	// read the reply and send its next request.
	var evicted []string
	rec := &sessionRecorder{ResponseWriter: w, admit: func(id string) {
		s.mu.Lock()
		evicted = s.addSession(id, operator)
		s.mu.Unlock()
	}}
	handler.ServeHTTP(rec, r)
	for _, old := range evicted {
		s.closeSDKSession(old)
	}
}

// sdkHandler returns the SDK's Streamable HTTP handler for the read-only or
// the operator tools, both built once.
func (s *HTTPServer) sdkHandler(operator bool) http.Handler {
	s.once.Do(func() {
		s.mu.Lock()
		if s.Evidence == nil {
			s.Evidence = ai.NewEvidenceStore()
		}

		store := s.Evidence
		s.mu.Unlock()
		reader := newSDKServer(s.Runner, s.Model, store, nil)
		s.sdk = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return reader },
			&mcp.StreamableHTTPOptions{JSONResponse: true, SessionTimeout: s.ttl()})
		if s.Operator != nil {
			// Event streams let the server ask the user to approve an action
			// in the middle of a tool call (MCP elicitation).
			op := newSDKServer(s.Runner, s.Model, store, s.Operator)
			s.sdkOperator = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return op },
				&mcp.StreamableHTTPOptions{SessionTimeout: s.ttl()})
		}
	})

	if operator && s.sdkOperator != nil {
		return s.sdkOperator
	}
	return s.sdk
}

// closeSDKSession ends a session in the SDK after Amass expires or evicts it.
// The session ID is unique, so it is closed in whichever handler holds it.
func (s *HTTPServer) closeSDKSession(id string) {
	if id == "" {
		return
	}

	for _, operator := range []bool{false, true} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, "/mcp", nil)
		if err != nil {
			return
		}

		req.Header.Set("Mcp-Session-Id", id)
		s.sdkHandler(operator).ServeHTTP(discardResponse{header: http.Header{}}, req)
		if s.sdkOperator == nil {
			return
		}
	}
}

// sessionRecorder notes the status the SDK writes and admits a new session
// when a successful reply names one.
type sessionRecorder struct {
	http.ResponseWriter
	status int
	admit  func(id string)
}

func (r *sessionRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
		if id := r.Header().Get("Mcp-Session-Id"); id != "" && code < 300 && r.admit != nil {
			r.admit(id)
		}
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *sessionRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
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
