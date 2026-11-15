// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	v1 "github.com/owasp-amass/amass/v5/engine/api/server/v1"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
	Code    int    `json:"code"`
}

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger
	dis    et.Dispatcher
	mgr    et.SessionManager
	ch     chan struct{}
	srv    *http.Server
	apiV1  *v1.V1Handlers
}

func NewServer(logger *slog.Logger, d et.Dispatcher, mgr et.SessionManager) (*Server, error) {
	r := mux.NewRouter()
	ctx, cancel := context.WithCancel(context.Background())

	apiV1, err := v1.NewV1Handlers(ctx, d, mgr, logger)
	if err != nil {
		cancel()
		return nil, err
	}

	srv := &Server{
		ctx:    ctx,
		cancel: cancel,
		log:    logger,
		dis:    d,
		mgr:    mgr,
		ch:     make(chan struct{}),
		srv: &http.Server{
			Addr:         ":4000",
			Handler:      r,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		apiV1: apiV1,
	}

	srv.routes(r)
	return srv, nil
}

func (s *Server) Start() error {
	s.log.Info("Server listening on", "addr", s.srv.Addr)
	err := s.srv.ListenAndServe()

	s.cancel()
	close(s.ch)
	return err
}

func (s *Server) Shutdown() error {
	err := s.srv.Shutdown(s.ctx)

	<-s.ch
	return err
}

// UUID route regex (common RFC 4122 form)
const uuidRE = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// Asset type route regex (tighten if you have an enum)
const assetTypeRE = `[a-z0-9][a-z0-9_-]{0,63}`

// maxRequestBody bounds a request body: a bulk request of the most items
// allowed fits, and no request can exhaust the engine's memory.
const maxRequestBody = 32 << 20

/*
Routes (v1)

GET    /api/v1/health
POST   /api/v1/sessions
GET	   /api/v1/sessions/list
DELETE /api/v1/sessions/{session_token}
GET    /api/v1/sessions/{session_token}/stats
GET    /api/v1/sessions/{session_token}/scope/{asset_type}
POST   /api/v1/sessions/{session_token}/assets/{asset_type}
POST   /api/v1/sessions/{session_token}/assets/{asset_type}:bulk
GET    /api/v1/sessions/{session_token}/ws/logs
*/
func (s *Server) routes(r *mux.Router) {
	r.Use(s.loggingMiddleware)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
			next.ServeHTTP(w, r)
		})
	})

	notAllowed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
	})
	// a path that a route serves with another method is not allowed, rather
	// than not found: mux reports a method mismatch in a sub-router as 404
	root := r
	notFound := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete} {
			other := req.Clone(req.Context())
			other.Method = m
			// Match is true for any path once a NotFoundHandler is set, so
			// only a matched route counts
			if rm := (&mux.RouteMatch{}); m != req.Method && root.Match(other, rm) && rm.Route != nil &&
				rm.MatchErr == nil {
				notAllowed(w, req)
				return
			}
		}

		writeError(w, http.StatusNotFound, "route not found", nil)
	})
	r.NotFoundHandler, r.MethodNotAllowedHandler = notFound, notAllowed

	// sub-routers answer with their own handlers, so each is given these
	sub := func(parent *mux.Router, prefix string) *mux.Router {
		s := parent.PathPrefix(prefix).Subrouter()
		s.NotFoundHandler, s.MethodNotAllowedHandler = notFound, notAllowed
		return s
	}

	v1 := sub(r, "/api/v1")
	v1.HandleFunc("/health", s.apiV1.HealthCheck).Methods(http.MethodGet)

	sessions := sub(v1, "/sessions")
	sessions.HandleFunc("", s.apiV1.CreateSessionHandler).Methods(http.MethodPost)
	sessions.HandleFunc("/list", s.apiV1.ListSessionsHandler).Methods(http.MethodGet)

	session := sub(sessions, "/{session_token:"+uuidRE+"}")
	session.HandleFunc("", s.apiV1.TerminateSessionHandler).Methods(http.MethodDelete)
	session.HandleFunc("/stats", s.apiV1.GetStatsHandler).Methods(http.MethodGet)

	scope := sub(session, "/scope")
	scope.HandleFunc("/{asset_type:"+assetTypeRE+"}", s.apiV1.GetScopeHandler).Methods(http.MethodGet)

	assets := sub(session, "/assets")
	// Single add: type in path (since OAM payload does not include it)
	assets.HandleFunc("/{asset_type:"+assetTypeRE+"}", s.apiV1.AddAssetTypedHandler).Methods(http.MethodPost)
	// Bulk add: :bulk suffix
	assets.HandleFunc("/{asset_type:"+assetTypeRE+"}:bulk", s.apiV1.AddAssetsBulkHandler).Methods(http.MethodPost)

	// WebSocket logs only
	ws := sub(session, "/ws")
	ws.HandleFunc("/logs", s.apiV1.WSLogsHandler).Methods(http.MethodGet)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("request completed", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string, err error) {
	out := ErrorResponse{Error: msg, Code: status}
	if err != nil {
		out.Details = err.Error()
	}
	writeJSON(w, status, out)
}
