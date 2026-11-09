// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPService exposes model-independent local classification. Absence of a
// trained artifact is an explicit abstain/escalate mode, never a prediction.
type HTTPService struct{ Model *LinearModel }

func (s HTTPService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, 200, map[string]any{"status": "running", "component": "classifier"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Model == nil {
			respondJSON(w, 200, map[string]any{"status": "ready", "mode": "evidence_triage", "trained": false, "routing": "review_or_escalate", "reason": "deterministic OAM evidence triage; no trained classifier weights"})
			return
		}
		respondJSON(w, 200, map[string]any{"status": "ready", "mode": "trained_model_loaded", "trained": true, "model_id": s.Model.ModelID, "task": s.Model.Task, "feature_version": s.Model.FeatureVersion})
	})
	mux.HandleFunc("GET /v1/model", func(w http.ResponseWriter, _ *http.Request) {
		if s.Model == nil {
			respondJSON(w, 200, map[string]any{"status": "evidence_triage", "decision": "review_or_escalate", "trained": false, "score_kind": "rules_no_probability"})
			return
		}
		respondJSON(w, 200, map[string]any{"status": "ready", "trained": true, "model_id": s.Model.ModelID, "task": s.Model.Task, "feature_version": s.Model.FeatureVersion, "features": s.Model.Features(), "score_kind": "uncalibrated_softmax"})
	})
	mux.HandleFunc("POST /v1/classify", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			respondJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "application/json required"})
			return
		}
		defer func() { _ = r.Body.Close() }()
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		d.DisallowUnknownFields()
		var input Input
		if err := d.Decode(&input); err != nil {
			respondJSON(w, 400, map[string]any{"error": "invalid feature vector"})
			return
		}
		var trailing any
		if err := d.Decode(&trailing); err != io.EOF {
			respondJSON(w, 400, map[string]any{"error": "unexpected trailing input"})
			return
		}
		if s.Model == nil {
			prediction, err := EvidenceTriage(input)
			if err != nil {
				respondJSON(w, 422, map[string]any{"error": err.Error()})
				return
			}
			respondJSON(w, 200, prediction)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		pred, err := s.Model.Classify(ctx, input)
		if err != nil {
			respondJSON(w, 422, map[string]any{"error": err.Error()})
			return
		}
		respondJSON(w, 200, pred)
	})
	return mux
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type HTTPClient struct {
	Endpoint string
	Client   *http.Client
}

var _ Classifier = HTTPClient{}

func (c HTTPClient) Classify(ctx context.Context, in Input) (Prediction, error) {
	var output Prediction
	if c.Endpoint == "" {
		return output, errors.New("classifier endpoint required")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return output, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.Endpoint, "/")+"/v1/classify", bytes.NewReader(body))
	if err != nil {
		return output, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return output, fmt.Errorf("classifier request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return output, fmt.Errorf("classifier unavailable or refused features: HTTP %d", resp.StatusCode)
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 16<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&output); err != nil {
		return output, fmt.Errorf("invalid classifier response: %w", err)
	}
	if output.ModelID == "" || output.FeatureVersion == "" || output.ScoreKind == "" {
		return output, errors.New("incomplete classifier response")
	}
	return output, nil
}
