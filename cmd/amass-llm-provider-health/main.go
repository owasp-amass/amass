// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Command amass-llm-provider-health verifies that the chosen LLM is
// actually responding. Probes are cached between health checks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// freshFor is how long a successful probe keeps the provider ready; probes
// run every five minutes while it is.
const freshFor = 7 * time.Minute

// target is the model the health check probes.
type target struct {
	model     llm.Model
	provider  string
	modelName string
	timeout   time.Duration
}

type state struct {
	sync.RWMutex
	ready     bool
	lastOK    time.Time
	lastError string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "amass-llm-provider-health:", err)
		os.Exit(1)
	}
}

func run() error {
	t, err := newTarget(os.LookupEnv)
	if err != nil {
		return err
	}

	var status state
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		status.probe(ctx, t)
		for {
			status.RLock()
			ready := status.ready
			status.RUnlock()
			interval := 20 * time.Second
			if ready {
				interval = 5 * time.Minute
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				status.probe(ctx, t)
			}
		}
	}()

	server := &http.Server{Addr: "0.0.0.0:8091", Handler: status.handler(t), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(closeCtx)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

// newTarget builds the model from the same AMASS_LLM_* environment the rest
// of Amass reads (config.ResolveAISettings, ai.NewModel). The API key is read
// from the variable AMASS_LLM_API_KEY_ENV names, or from AMASS_LLM_API_KEY.
func newTarget(lookup func(string) (string, bool)) (target, error) {
	s, err := config.ResolveAISettings(config.AISettings{Provider: "compatible"}, lookup)
	if err != nil {
		return target{}, err
	}

	m, timeout, ok, err := ai.MainModel(s, lookup)
	if err != nil {
		return target{}, err
	}
	if !ok {
		return target{}, errors.New("AMASS_LLM_MODEL and AMASS_LLM_ENDPOINT must be configured")
	}
	return target{model: m, provider: s.Provider, modelName: s.Model, timeout: timeout}, nil
}

// probe asks the model for a short reply and records whether a usable one
// came back.
func (s *state) probe(ctx context.Context, t target) {
	check, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	response, err := t.model.Generate(check, []llm.Message{
		{Role: "system", Text: "Model connectivity check. Reply briefly with READY."},
		{Role: "user", Text: "READY"},
	}, nil)
	if err == nil && strings.TrimSpace(response.Text) == "" && len(response.Calls) == 0 {
		err = errors.New("model responded without usable content")
	}

	s.Lock()
	s.ready = err == nil
	if err == nil {
		s.lastOK = time.Now()
		s.lastError = ""
	} else {
		s.lastError = err.Error()
	}
	s.Unlock()

	if err != nil {
		fmt.Fprintln(os.Stderr, "inference probe unsuccessful:", err)
	} else {
		fmt.Fprintln(os.Stderr, "inference model responded:", t.provider, t.modelName)
	}
}

// handler serves /healthz, which answers while the process runs, and /readyz,
// which answers 200 only while the last probe succeeded within freshFor. The
// probe's error stays in the container log: it can carry upstream details.
func (s *state) handler(t target) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		send(w, http.StatusOK, map[string]any{"status": "running", "component": "inference-provider"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		s.RLock()
		ready, lastOK := s.ready, s.lastOK
		s.RUnlock()

		status, code := "not_ready", http.StatusServiceUnavailable
		if ready && !lastOK.IsZero() && time.Since(lastOK) < freshFor {
			status, code = "ready", http.StatusOK
		}
		send(w, code, map[string]any{"status": status, "provider": t.provider, "model": t.modelName,
			"last_success": lastOK})
	})
	return mux
}

func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
