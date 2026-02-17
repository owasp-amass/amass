// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeop "github.com/owasp-amass/open-asset-model/people"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger
	dis    et.Dispatcher
	mgr    et.SessionManager
	ch     chan struct{}
	srv    *http.Server
}

func NewServer(logger *slog.Logger, d et.Dispatcher, mgr et.SessionManager) *Server {
	r := mux.NewRouter()

	ctx, cancel := context.WithCancel(context.Background())
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
	}

	srv.routes(r)
	return srv
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

/*
Routes (v1)

POST   /v1/sessions
GET	   /v1/sessions/list
DELETE /v1/sessions/{session_token}
GET    /v1/sessions/{session_token}/stats
GET    /v1/sessions/{session_token}/scope/{asset_type}
POST   /v1/sessions/{session_token}/assets/{asset_type}
POST   /v1/sessions/{session_token}/assets/{asset_type}:bulk
GET    /v1/sessions/{session_token}/ws/logs
*/
func (s *Server) routes(r *mux.Router) {
	r.Use(s.loggingMiddleware)

	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "route not found", nil)
	})
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
	})

	v1 := r.PathPrefix("/v1").Subrouter()
	sessions := v1.PathPrefix("/sessions").Subrouter()
	sessions.HandleFunc("", s.createSessionHandler).Methods(http.MethodPost)
	sessions.HandleFunc("/list", s.listSessionsHandler).Methods(http.MethodGet)

	session := sessions.PathPrefix("/{session_token:" + uuidRE + "}").Subrouter()
	session.HandleFunc("", s.terminateSessionHandler).Methods(http.MethodDelete)
	session.HandleFunc("/stats", s.getStatsHandler).Methods(http.MethodGet)

	scope := session.PathPrefix("/scope").Subrouter()
	scope.HandleFunc("/{asset_type:"+assetTypeRE+"}", s.getScopeHandler).Methods(http.MethodGet)

	assets := session.PathPrefix("/assets").Subrouter()
	// Single add: type in path (since OAM payload does not include it)
	assets.HandleFunc("/{asset_type:"+assetTypeRE+"}", s.addAssetTypedHandler).Methods(http.MethodPost)
	// Bulk add: :bulk suffix
	assets.HandleFunc("/{asset_type:"+assetTypeRE+"}:bulk", s.addAssetsBulkHandler).Methods(http.MethodPost)

	// WebSocket logs only
	ws := session.PathPrefix("/ws").Subrouter()
	ws.HandleFunc("/logs", s.wsLogsHandler).Methods(http.MethodGet)
}

/* ----------------------------- Helpers ----------------------------- */

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string, err error) {
	type resp struct {
		Error   string `json:"error"`
		Details string `json:"details,omitempty"`
		Code    int    `json:"code"`
	}

	out := resp{Error: msg, Code: status}
	if err != nil {
		out.Details = err.Error()
	}

	writeJSON(w, status, out)
}

func readRawJSON(r *http.Request) (json.RawMessage, error) {
	var raw json.RawMessage
	defer func() { _ = r.Body.Close() }()

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, ErrBadRequest
	}
	return raw, nil
}

func looksLikeJSONObject(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) >= 2 && raw[0] == '{' && raw[len(raw)-1] == '}'
}

func (s *Server) PutAsset(ctx context.Context, sess et.Session, asset oam.Asset) (string, error) {
	filter, err := defaultContentFilter(asset)
	if err != nil {
		return "", err
	}

	var entity *dbt.Entity
	ents, err := sess.DB().FindEntitiesByContent(ctx, asset.AssetType(), time.Time{}, 1, filter)
	if err == nil {
		entity = ents[0]
	} else {
		entity, err = sess.DB().CreateAsset(ctx, asset)
		if err != nil {
			return entity.ID, err
		}
	}

	// Create and schedule new event
	event := &et.Event{
		Name:       asset.Key(),
		Entity:     entity,
		Dispatcher: s.dis,
		Session:    sess,
	}

	if err := s.dis.DispatchEvent(event); err != nil {
		return "", err
	}
	return entity.ID, nil
}

func (s *Server) PutAssets(ctx context.Context, sess et.Session, assets []oam.Asset) (int64, error) {
	ch := make(chan error, 100)

	for _, asset := range assets {
		go func(a oam.Asset) {
			_, err := s.PutAsset(ctx, sess, a)
			ch <- err
		}(asset)
	}

	var failed int64
	for range assets {
		if err := <-ch; err != nil {
			failed++
		}
	}
	close(ch)

	if failed != 0 {
		s.log.Warn("some assets failed to ingest", "failed", failed, "total", len(assets))
	}
	return int64(len(assets)) - failed, nil
}

func parseAsset(atype string, raw json.RawMessage) (oam.Asset, error) {
	switch atype {
	case strings.ToLower(string(oam.Account)):
		var a oamacct.Account
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.AutnumRecord)):
		var a oamreg.AutnumRecord
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.AutonomousSystem)):
		var a oamnet.AutonomousSystem
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.ContactRecord)):
		var a oamcon.ContactRecord
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.DomainRecord)):
		var a oamreg.DomainRecord
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.File)):
		var a oamfile.File
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.FQDN)):
		var a oamdns.FQDN
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.FundsTransfer)):
		var a oamfin.FundsTransfer
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Identifier)):
		var a oamgen.Identifier
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.IPAddress)):
		var a oamnet.IPAddress
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.IPNetRecord)):
		var a oamreg.IPNetRecord
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Location)):
		var a oamcon.Location
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Netblock)):
		var a oamnet.Netblock
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Organization)):
		var a oamorg.Organization
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Phone)):
		var a oamcon.Phone
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Person)):
		var a oampeop.Person
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Product)):
		var a oamplat.Product
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.ProductRelease)):
		var a oamplat.ProductRelease
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.Service)):
		var a oamplat.Service
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.TLSCertificate)):
		var a oamcert.TLSCertificate
		err := json.Unmarshal(raw, &a)
		return &a, err
	case strings.ToLower(string(oam.URL)):
		var a oamurl.URL
		err := json.Unmarshal(raw, &a)
		return &a, err
	}
	return nil, fmt.Errorf("unknown asset type: %s", atype)
}

func defaultContentFilter(asset oam.Asset) (dbt.ContentFilters, error) {
	switch asset.AssetType() {
	case oam.Account:
		return dbt.ContentFilters{"unique_id": asset.Key()}, nil
	case oam.AutnumRecord:
		return dbt.ContentFilters{"handle": asset.Key()}, nil
	case oam.AutonomousSystem:
		return dbt.ContentFilters{"number": asset.Key()}, nil
	case oam.ContactRecord:
		return dbt.ContentFilters{"discovered_at": asset.Key()}, nil
	case oam.DomainRecord:
		return dbt.ContentFilters{"domain": asset.Key()}, nil
	case oam.File:
		return dbt.ContentFilters{"url": asset.Key()}, nil
	case oam.FQDN:
		return dbt.ContentFilters{"name": asset.Key()}, nil
	case oam.FundsTransfer:
		return dbt.ContentFilters{"unique_id": asset.Key()}, nil
	case oam.Identifier:
		return dbt.ContentFilters{"unique_id": asset.Key()}, nil
	case oam.IPAddress:
		return dbt.ContentFilters{"address": asset.Key()}, nil
	case oam.IPNetRecord:
		return dbt.ContentFilters{"handle": asset.Key()}, nil
	case oam.Location:
		return dbt.ContentFilters{"address": asset.Key()}, nil
	case oam.Netblock:
		return dbt.ContentFilters{"cidr": asset.Key()}, nil
	case oam.Organization:
		return dbt.ContentFilters{"unique_id": asset.Key()}, nil
	case oam.Person:
		return dbt.ContentFilters{"unique_id": asset.Key()}, nil
	case oam.Phone:
		return dbt.ContentFilters{"e164": asset.Key()}, nil
	case oam.Product:
		return dbt.ContentFilters{"unique_id": asset.Key()}, nil
	case oam.ProductRelease:
		return dbt.ContentFilters{"name": asset.Key()}, nil
	case oam.Service:
		return dbt.ContentFilters{"unique_id": asset.Key()}, nil
	case oam.TLSCertificate:
		return dbt.ContentFilters{"serial_number": asset.Key()}, nil
	case oam.URL:
		return dbt.ContentFilters{"url": asset.Key()}, nil
	}

	return nil, errors.New("invalid asset type")
}
