// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestNewTarget(t *testing.T) {
	good := map[string]string{"AMASS_LLM_MODEL": "qwen3", "AMASS_LLM_ENDPOINT": "https://llm.example.com/v1/chat/completions"}
	tg, err := newTarget(env(good))
	if err != nil {
		t.Fatal(err)
	}
	if tg.provider != "compatible" || tg.modelName != "qwen3" || tg.timeout != ai.DefaultMainModelTimeout || tg.model == nil {
		t.Errorf("target = %+v", tg)
	}

	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tg, err = newTarget(env(with(map[string]string{"AMASS_LLM_MODEL_TIMEOUT": "30s"})))
	if err != nil || tg.timeout != 30*time.Second {
		t.Errorf("timeout = %v, %v", tg.timeout, err)
	}
	if _, err := newTarget(env(with(map[string]string{"AMASS_LLM_PROVIDER": "anthropic",
		"AMASS_LLM_ENDPOINT": "https://api.anthropic.com/v1/messages", "AMASS_LLM_API_KEY": "k"}))); err != nil {
		t.Errorf("anthropic with a key: %v", err)
	}
	if _, err := newTarget(env(with(map[string]string{"AMASS_LLM_PROVIDER": "anthropic", "AMASS_LLM_API_KEY_ENV": "MY_KEY",
		"MY_KEY": "k"}))); err != nil {
		t.Errorf("anthropic with the key in a named variable: %v", err)
	}

	for name, m := range map[string]map[string]string{
		"no model":           {"AMASS_LLM_ENDPOINT": "https://llm.example.com"},
		"no endpoint":        {"AMASS_LLM_MODEL": "qwen3"},
		"remote plain HTTP":  with(map[string]string{"AMASS_LLM_ENDPOINT": "http://llm.example.com/v1/chat/completions"}),
		"credentials in URL": with(map[string]string{"AMASS_LLM_ENDPOINT": "https://u:p@llm.example.com/v1"}),
		"short timeout":      with(map[string]string{"AMASS_LLM_MODEL_TIMEOUT": "1s"}),
		"small context":      with(map[string]string{"AMASS_LLM_CONTEXT_TOKENS": "100"}),
		"unknown provider":   with(map[string]string{"AMASS_LLM_PROVIDER": "nope"}),
		"anthropic, no key":  with(map[string]string{"AMASS_LLM_PROVIDER": "anthropic"}),
	} {
		if _, err := newTarget(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// plain HTTP is allowed when the operator says so
	if _, err := newTarget(env(with(map[string]string{"AMASS_LLM_ENDPOINT": "http://llm.internal:8000/v1/chat/completions",
		"AMASS_LLM_ALLOW_HTTP": "true"}))); err != nil {
		t.Errorf("allowed plain HTTP: %v", err)
	}
}

type fakeModel struct {
	reply llm.Response
	err   error
}

func (f fakeModel) Generate(context.Context, []llm.Message, []llm.ToolSpec) (llm.Response, error) {
	return f.reply, f.err
}

func readyz(t *testing.T, h http.Handler) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return rec.Code, body
}

func TestProbeAndReadiness(t *testing.T) {
	var s state
	tg := target{provider: "compatible", modelName: "qwen3", timeout: time.Second}
	h := s.handler(tg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("healthz = %d %v", rec.Code, rec.Header())
	}
	if code, body := readyz(t, h); code != http.StatusServiceUnavailable || body["status"] != "not_ready" {
		t.Errorf("before any probe: %d %v", code, body)
	}

	tg.model = fakeModel{reply: llm.Response{Text: "READY"}}
	s.probe(context.Background(), tg)
	if code, body := readyz(t, h); code != http.StatusOK || body["status"] != "ready" || body["model"] != "qwen3" {
		t.Errorf("after a good probe: %d %v", code, body)
	}

	// an empty reply or an error makes the provider not ready, and the
	// error is not served
	for _, m := range []fakeModel{{reply: llm.Response{Text: "  "}}, {err: errors.New("upstream token sk-123 rejected")}} {
		tg.model = m
		s.probe(context.Background(), tg)
		code, body := readyz(t, h)
		if code != http.StatusServiceUnavailable {
			t.Errorf("after %+v: %d", m, code)
		}
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), "sk-123") {
			t.Errorf("the probe error was served: %s", raw)
		}
	}

	// a success that is too old is not ready
	s.Lock()
	s.ready, s.lastOK = true, time.Now().Add(-freshFor-time.Minute)
	s.Unlock()
	if code, _ := readyz(t, h); code != http.StatusServiceUnavailable {
		t.Errorf("a stale success is ready: %d", code)
	}
}
