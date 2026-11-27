// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/owasp-amass/amass/v5/config"
	apiclient "github.com/owasp-amass/amass/v5/engine/api/client"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const maxBulkItems = 5000

type HealthCheckResponse struct {
	Result string `json:"result"`
}

type CreateSessionResponse struct {
	SessionToken string `json:"sessionToken"`
	// JobID is the job the session works on: its own token, or a running
	// job of the same scope that it joined, taking that job's configuration.
	JobID  string `json:"jobId,omitempty"`
	Joined bool   `json:"joined,omitempty"`
}

type ListSessionsResponse struct {
	SessionTokens []string `json:"sessionTokens"`
}

type SessionStatsResponse struct {
	WorkItemsCompleted int `json:"workItemsCompleted"`
	WorkItemsTotal     int `json:"workItemsTotal"`
}

type ScopeResponse struct {
	Data []json.RawMessage `json:"data"`
}

type AddAssetResponse struct {
	EntityID string `json:"entityID"`
}

// Bulk typed add: {"items":[ <OAM obj>, <OAM obj>, ... ]}
// where each item is arbitrary JSON object without "type".
type BulkAddAssetsRequest struct {
	Items []json.RawMessage `json:"items"`
}

type BulkAddAssetsResponse struct {
	Ingested int64 `json:"ingested"`
	Stored   int64 `json:"stored"`
	Failed   int64 `json:"failed"`
}

var (
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
)

type V1Handlers struct {
	ctx context.Context
	log *slog.Logger
	dis et.Dispatcher
	mgr et.SessionManager
}

// session returns the session the request's session_token names, or answers
// the request with 400 for a malformed token or 404 for an unknown or
// terminated session.
func (v *V1Handlers) session(w http.ResponseWriter, r *http.Request) (et.Session, bool) {
	token, err := uuid.Parse(mux.Vars(r)["session_token"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return nil, false
	}
	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return nil, false
	}
	return sess, true
}

func NewV1Handlers(ctx context.Context, dis et.Dispatcher, mgr et.SessionManager, log *slog.Logger) (*V1Handlers, error) {
	return &V1Handlers{
		ctx: ctx,
		log: log,
		dis: dis,
		mgr: mgr,
	}, nil
}

// HealthCheck godoc
//
// @Summary      Health check
// @Description  Returns a simple health indicator that the Amass Engine API is running.
// @Tags         system
// @Produce      json
// @Success      200  {object}  HealthCheckResponse
// @Router       /health [get]
func (v *V1Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	resp := HealthCheckResponse{Result: "Amass Engine OK"}

	writeJSON(w, http.StatusOK, resp)
}

// CreateSessionHandler godoc
//
// @Summary      Create a new engine session
// @Description  Creates a new Amass engine session using the provided configuration JSON.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        config  body      config.Config  true  "Engine configuration"
// @Success      201     {object}  CreateSessionResponse
// @Failure      400     {object}  ErrorResponse  "Invalid JSON or invalid configuration"
// @Failure      500     {object}  ErrorResponse  "Failed to create session"
// @Router       /sessions [post]
func (v *V1Handlers) CreateSessionHandler(w http.ResponseWriter, r *http.Request) {
	raw, err := readRawJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	// minimal validation: ensure it’s valid JSON object
	if !looksLikeJSONObject(raw) {
		writeError(w, http.StatusBadRequest, "invalid JSON object", nil)
		return
	}

	var config config.Config
	if err := json.Unmarshal(raw, &config); err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration", err)
		return
	}
	if config.Scope == nil {
		writeError(w, http.StatusBadRequest, "invalid configuration", errors.New("the configuration has no scope"))
		return
	}
	// Populate FROM/TO in transformations
	for k, t := range config.Transformations {
		_ = t.Split(k)
	}

	sess, err := v.mgr.NewSession(&config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session", err)
		return
	}

	resp := CreateSessionResponse{SessionToken: sess.ID().String()}
	if j, ok := sess.(interface{ Job() (string, bool) }); ok {
		resp.JobID, resp.Joined = j.Job()
	}
	writeJSON(w, http.StatusCreated, resp)
}

// ListSessionsHandler godoc
//
// @Summary      List active sessions
// @Description  Returns the session tokens for all currently active sessions.
// @Tags         sessions
// @Produce      json
// @Success      200  {object}  ListSessionsResponse
// @Router       /sessions/list [get]
func (v *V1Handlers) ListSessionsHandler(w http.ResponseWriter, r *http.Request) {
	// An engine with no sessions answers with an empty list, so a client can
	// tell that a session it knew of is gone.
	resp := ListSessionsResponse{SessionTokens: []string{}}
	for _, sess := range v.mgr.GetSessions() {
		resp.SessionTokens = append(resp.SessionTokens, sess.ID().String())
	}

	writeJSON(w, http.StatusOK, resp)
}

// TerminateSessionHandler godoc
//
// @Summary      Terminate a session
// @Description  Cancels an active session. Returns no content on success.
// @Tags         sessions
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      204
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /sessions/{session_token} [delete]
func (v *V1Handlers) TerminateSessionHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := v.session(w, r)
	if !ok {
		return
	}

	go v.mgr.CancelSession(sess.ID())
	w.WriteHeader(http.StatusNoContent)
}

// GetStatsHandler godoc
//
// @Summary      Get session statistics
// @Description  Returns the current runtime statistics for a session.
// @Tags         sessions
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      200  {object}  SessionStatsResponse
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /sessions/{session_token}/stats [get]
func (v *V1Handlers) GetStatsHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := v.session(w, r)
	if !ok {
		return
	}
	// encode under the lock, and write after it, so a slow client does not
	// hold up the session's updates
	stats := sess.Stats()
	stats.RLock()
	body, err := json.Marshal(stats)
	stats.RUnlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode the statistics", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

// WorkersResponse lists the workers of a session's job.
type WorkersResponse struct {
	Workers []et.WorkerStats `json:"workers"`
}

// GetWorkersHandler godoc
//
// @Summary      Get the workers of a session's job
// @Description  Returns the engine sessions working on the session's job, on a database the engines share work
// @Description  through: whether each is still there, its background work, and the items it holds and did.
// @Tags         sessions
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      200  {object}  WorkersResponse
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /sessions/{session_token}/workers [get]
func (v *V1Handlers) GetWorkersHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := v.session(w, r)
	if !ok {
		return
	}

	resp := WorkersResponse{Workers: []et.WorkerStats{}}
	if s, ok := sess.(interface{ Workers() []et.WorkerStats }); ok {
		if ws := s.Workers(); ws != nil {
			resp.Workers = ws
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetScopeHandler godoc
//
// @Summary      Get session scope for an asset type
// @Description  Returns the scoped assets for the given session and asset type as an array of raw OAM JSON objects.
// @Tags         scope
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Param        asset_type     path  string  true  "Asset type (e.g., autonomoussystem, fqdn, ipaddress, netblock, streetaddress, organization)"
// @Success      200  {object}  ScopeResponse  "Response contains a 'data' array of raw OAM JSON"
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found or scope not found for asset type"
// @Router       /sessions/{session_token}/scope/{asset_type} [get]
func (v *V1Handlers) GetScopeHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := v.session(w, r)
	if !ok {
		return
	}
	assetType := strings.ToLower(strings.TrimSpace(mux.Vars(r)["asset_type"]))

	var assets []oam.Asset
	switch assetType {
	case strings.ToLower(string(oam.AutonomousSystem)):
		for _, a := range sess.Scope().AutonomousSystems() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.FQDN)):
		for _, a := range sess.Scope().FQDNs() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.IPAddress)):
		for _, a := range sess.Scope().IPAddresses() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Netblock)):
		for _, a := range sess.Scope().Netblocks() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.StreetAddress)):
		for _, a := range sess.Scope().StreetAddresses() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Organization)):
		for _, a := range sess.Scope().Organizations() {
			assets = append(assets, a)
		}
	}

	if len(assets) == 0 {
		writeError(w, http.StatusNotFound,
			"session scope not found for the selected asset type", ErrNotFound)
		return
	}

	jsonArray := make([]json.RawMessage, len(assets))
	for i, a := range assets {
		if raw, err := a.JSON(); err == nil {
			jsonArray[i] = json.RawMessage(raw)
		}
	}

	writeJSON(w, http.StatusOK, ScopeResponse{Data: jsonArray})
}

// AddAssetTypedHandler godoc
//
// @Summary      Add a single asset (typed by path)
// @Description  Submits a single OAM asset to the session. The asset type is provided in the URL path; the request body is a raw OAM JSON object without a 'type' field.
// @Tags         assets
// @Accept       json
// @Produce      json
// @Param        session_token  path  string          true  "Session token (UUID)"
// @Param        asset_type     path  string          true  "Asset type (e.g., autonomous_system, fqdn, ipaddress, netblock, streetaddress, organization)"
// @Param        asset          body  json.RawMessage true  "Raw OAM JSON object (without 'type')"
// @Success      200            {object}  AddAssetResponse
// @Failure      400            {object}  ErrorResponse  "Invalid session token, invalid JSON, or invalid asset object"
// @Failure      404            {object}  ErrorResponse  "Session not found"
// @Failure      500            {object}  ErrorResponse  "Failed to submit the asset"
// @Router       /sessions/{session_token}/assets/{asset_type} [post]
func (v *V1Handlers) AddAssetTypedHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := v.session(w, r)
	if !ok {
		return
	}
	assetType := strings.ToLower(strings.TrimSpace(mux.Vars(r)["asset_type"]))

	raw, err := readRawJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	// minimal validation: ensure it’s valid JSON object
	if !looksLikeJSONObject(raw) {
		writeError(w, http.StatusBadRequest, "invalid JSON object", nil)
		return
	}

	asset, err := apiclient.ParseAsset(assetType, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid asset object", err)
		return
	}

	eid, err := v.PutAsset(v.ctx, sess, asset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit the asset", err)
		return
	}

	writeJSON(w, http.StatusOK, AddAssetResponse{
		EntityID: eid,
	})
}

// AddAssetsBulkHandler godoc
//
// @Summary      Add assets in bulk (typed by path)
// @Description  Submits multiple OAM assets to the session in one request. The asset type is provided in the URL path. Each item in 'items' is a raw OAM JSON object without a 'type' field.
// @Tags         assets
// @Accept       json
// @Produce      json
// @Param        session_token  path  string               true  "Session token (UUID)"
// @Param        asset_type     path  string               true  "Asset type (e.g., autonomous_system, fqdn, ipaddress, netblock, streetaddress, organization)"
// @Param        request        body  BulkAddAssetsRequest true  "Bulk add request payload"
// @Success      200            {object}  BulkAddAssetsResponse
// @Failure      400            {object}  ErrorResponse  "Invalid session token, invalid JSON, empty items, or no valid items"
// @Failure      404            {object}  ErrorResponse  "Session not found"
// @Failure      413            {object}  ErrorResponse  "Too many items in bulk request"
// @Failure      500            {object}  BulkAddAssetsResponse  "Server failure (response includes ingested/stored/failed)"
// @Router       /sessions/{session_token}/assets/{asset_type}:bulk [post]
func (v *V1Handlers) AddAssetsBulkHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := v.session(w, r)
	if !ok {
		return
	}
	assetType := strings.ToLower(strings.TrimSpace(mux.Vars(r)["asset_type"]))

	var req BulkAddAssetsRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items must be non-empty", nil)
		return
	}
	if len(req.Items) > maxBulkItems {
		writeError(w, http.StatusRequestEntityTooLarge,
			"too many items in bulk request", errors.New("max items exceeded"))
		return
	}

	assets := make([]oam.Asset, 0, len(req.Items))
	for _, raw := range req.Items {
		if a, err := apiclient.ParseAsset(assetType, raw); err == nil {
			assets = append(assets, a)
		}
	}

	// Ingested counts the items that are assets of the type; Failed counts
	// every item that was not stored, including those that were not.
	ingested := int64(len(assets))
	if ingested == 0 {
		writeError(w, http.StatusBadRequest, "no valid JSON objects in items", nil)
		return
	}

	status := http.StatusOK
	stored, err := v.PutAssets(v.ctx, sess, assets)
	if err != nil {
		status, stored = http.StatusInternalServerError, 0
	}
	writeJSON(w, status, BulkAddAssetsResponse{
		Ingested: ingested,
		Stored:   stored,
		Failed:   int64(len(req.Items)) - stored,
	})
}
