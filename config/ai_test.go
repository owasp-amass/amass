// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAISettingsYAMLAndEnvironmentPrecedence(t *testing.T) {
	c := loadYAML(t, `options:
  ai:
    provider: compatible
    endpoint: http://model:11434/v1/chat/completions
    model: qwen3:8b
    model_timeout: 4m
    investigation_timeout: 12m
    depth: 8
    max_paths_per_asset: 3
    allow_http: true
    classifier_model: /models/classifier.json
    classifier_review: false
    documents:
      enabled: true
      provider: ollama
      model: qwen3:8b
`)
	if c.AI.Documents == nil || !c.AI.DocumentModelEnabled() {
		t.Fatalf("options.ai.documents failed to decode: %+v", c.AI.Documents)
	}
	if c.AI == nil || c.AI.Model != "qwen3:8b" || c.AI.MaxDepth != 8 || !c.AI.AllowHTTP {
		t.Fatalf("YAML section failed to decode: %+v", c.AI)
	}

	env := map[string]string{
		"AMASS_LLM_MODEL":         "qwen3:14b",
		"AMASS_LLM_DEPTH":         "12",
		"AMASS_CLASSIFIER_REVIEW": "true",
		"AMASS_LLM_MODEL_TIMEOUT": "6m",
	}
	out, err := ResolveAISettings(*c.AI, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if out.Model != "qwen3:14b" || out.MaxDepth != 12 || !out.ClassifierReview ||
		out.Endpoint != "http://model:11434/v1/chat/completions" || out.ModelTimeout != "6m" {
		t.Fatalf("environment precedence incorrectly applied: %+v", out)
	}
}

func TestAISettingsInvalidEnvironmentValuesFailClosed(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"AMASS_LLM_ALLOW_HTTP", "maybe"},
		{"AMASS_LLM_MODEL_TIMEOUT", "zero"},
		{"AMASS_LLM_INVESTIGATION_TIMEOUT", "0s"},
		{"AMASS_LLM_MAX_PATHS_PER_ASSET", "-1"},
		{"AMASS_LLM_GUIDANCE_ROUNDS", "4"},
		{"AMASS_LLM_DEPTH", "x"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			_, err := ResolveAISettings(AISettings{}, func(k string) (string, bool) {
				if k == tc.key {
					return tc.value, true
				}

				return "", false
			})
			if err == nil {
				t.Fatalf("invalid AI setting %s=%s was accepted", tc.key, tc.value)
			}
			if !strings.Contains(err.Error(), "AI") && !strings.Contains(err.Error(),
				"timeout") && !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("missing setting context: %v", err)
			}
		})
	}
}

func TestAISettingsDisabledByDefault(t *testing.T) {
	c := NewConfig()
	if c.AI != nil {
		t.Fatalf("AI is not an opt-in section: %+v", c.AI)
	}
}

func TestResolveAISettingsTokensAndTemperature(t *testing.T) {
	env := map[string]string{"AMASS_LLM_MAX_TOKENS": "2048", "AMASS_LLM_TEMPERATURE": "0"}
	got, err := ResolveAISettings(AISettings{}, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil || got.MaxTokens != 2048 || got.Temperature != "0" {
		t.Fatalf("got %+v err=%v", got, err)
	}
	if v, err := ParseAITemperature(got.Temperature); err != nil || v == nil || *v != 0 {
		t.Fatalf("temperature 0 must be explicit, got %v err=%v", v, err)
	}
	if v, err := ParseAITemperature(""); err != nil || v != nil {
		t.Fatalf("empty temperature must mean provider default, got %v err=%v", v, err)
	}
	for _, bad := range []AISettings{{Temperature: "2.5"}, {Temperature: "warm"}, {MaxTokens: 200000}} {
		if _, err := ResolveAISettings(bad, func(string) (string, bool) { return "", false }); err == nil {
			t.Errorf("expected rejection of %+v", bad)
		}
	}
}

func TestResolveAISettingsOllamaOptions(t *testing.T) {
	env := map[string]string{"AMASS_LLM_CONTEXT_TOKENS": "16384", "AMASS_LLM_THINK": "true"}
	got, err := ResolveAISettings(AISettings{}, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil || got.ContextTokens != 16384 || !got.Think {
		t.Fatalf("got %+v err=%v", got, err)
	}
	for _, bad := range []AISettings{{ContextTokens: 512}, {ContextTokens: 1 << 20}} {
		if _, err := ResolveAISettings(bad, func(string) (string, bool) { return "", false }); err == nil {
			t.Errorf("expected rejection of %+v", bad)
		}
	}
}

// The document model is off unless enabled, never borrows the main model, and
// an enabled one needs a known provider and a model.
func TestDocumentModelSettings(t *testing.T) {
	var none *AISettings
	if none.DocumentModelEnabled() || none.DocumentsShared() {
		t.Error("no ai section enables the document model")
	}

	main := &AISettings{Provider: "ollama", Model: "qwen3:8b"}
	if main.DocumentModelEnabled() {
		t.Error("the main model must not read documents")
	}

	off := &AISettings{Documents: &DocumentModelSettings{Provider: "nonsense"}}
	if off.DocumentModelEnabled() || off.Documents.Validate() != nil {
		t.Error("a disabled document model is neither enabled nor checked")
	}

	on := &AISettings{Documents: &DocumentModelSettings{Enabled: true, Provider: "ollama", Model: "qwen3:8b"}}
	if !on.DocumentModelEnabled() || on.DocumentsShared() || on.Documents.Validate() != nil {
		t.Errorf("enabled document model %+v", on.Documents)
	}
	on.Documents.ShareWithAssistants = true
	if !on.DocumentsShared() {
		t.Error("share_with_assistants shares the passages")
	}

	for _, bad := range []DocumentModelSettings{
		{Enabled: true, Provider: "other", Model: "m"},
		{Enabled: true, Provider: "anthropic"},
		{Enabled: true, Provider: "ollama", Model: "m", ModelTimeout: "1s"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}

	if _, err := ResolveAISettings(AISettings{Documents: &DocumentModelSettings{Enabled: true}},
		func(string) (string, bool) { return "", false }); err == nil {
		t.Error("an enabled document model without a provider was accepted")
	}
}

// The AI settings live under options.ai: a top-level ai section, a mistyped
// key and an invalid document model all stop the load rather than being
// ignored.
func TestAISettingsRefusedOutsideOptions(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{"ai:\n  model: qwen3:8b\n", "moved to options.ai"},
		{"options:\n  ai:\n    modle: qwen3:8b\n", "options.ai"},
		{"options:\n  ai:\n    documents:\n      enabled: true\n      provider: ollama\n", "options.ai.documents.model"},
	} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewConfig().LoadSettings(p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q loaded with %v, want an error naming %q", tc.yaml, err, tc.want)
		}
	}

	if c := loadYAML(t, "seed:\n  domains:\n    - example.com\n"); c.AI != nil {
		t.Errorf("no options.ai still set AI: %+v", c.AI)
	}
}

// Only an explicit options.ai key counts as set, so a document model section
// does not change the question model's guidance rounds.
func TestAIKeySet(t *testing.T) {
	c := loadYAML(t, "options:\n  ai:\n    documents:\n      enabled: true\n      provider: ollama\n      model: m\n")
	if c.AIKeySet("guidance_rounds") {
		t.Error("guidance_rounds reported set when only documents is")
	}
	c = loadYAML(t, "options:\n  ai:\n    guidance_rounds: 0\n")
	if !c.AIKeySet("guidance_rounds") || c.AI.GuidanceRounds != 0 {
		t.Error("an explicit guidance_rounds: 0 is not reported set")
	}
	if NewConfig().AIKeySet("guidance_rounds") {
		t.Error("a config without options.ai reports a key set")
	}

	for _, bad := range []DocumentModelSettings{
		{Enabled: true, Provider: "ollama", Model: "m", MaxLeads: -2},
		{Enabled: true, Provider: "ollama", Model: "m", ContextTokens: 1024},
		{Enabled: true, Provider: "ollama", Model: "m", ChunkChars: 100},
		{Enabled: true, Provider: "ollama", Model: "m", Hold: "-1m"},
		{Enabled: true, Provider: "ollama", Model: "m", Hold: "3h"},
		{Enabled: true, Provider: "ollama", Model: "m", Hold: "soon"},
		{Enabled: true, Provider: "ollama", Model: "m", DocumentTimeout: "-1m"},
		{Enabled: true, Provider: "ollama", Model: "m", DocumentTimeout: "7h"},
		{Enabled: true, Provider: "ollama", Model: "m", MaxChunks: -1},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

// The hold is unset unless given; 0 is a hold of none, not unset.
func TestDocumentModelHold(t *testing.T) {
	var nilSettings *DocumentModelSettings
	if _, ok := nilSettings.HoldDuration(); ok {
		t.Error("settings that are absent report a hold")
	}
	for in, want := range map[string]time.Duration{"0": 0, "5m": 5 * time.Minute, " 90s ": 90 * time.Second} {
		d := DocumentModelSettings{Enabled: true, Provider: "ollama", Model: "m", Hold: in}
		if err := d.Validate(); err != nil {
			t.Errorf("hold %q: %v", in, err)
		}
		if got, ok := d.HoldDuration(); !ok || got != want {
			t.Errorf("hold %q = %v, %v; want %v", in, got, ok, want)
		}
	}
	if _, ok := (&DocumentModelSettings{}).HoldDuration(); ok {
		t.Error("an empty hold is reported set")
	}
}

// The document timeout defaults to 10 minutes; 0 sets no bound.
func TestDocumentTimeout(t *testing.T) {
	var nilSettings *DocumentModelSettings
	for in, want := range map[string]time.Duration{"": DefaultDocumentTimeout, "0": 0, "25m": 25 * time.Minute} {
		d := DocumentModelSettings{Enabled: true, Provider: "ollama", Model: "m", DocumentTimeout: in, MaxChunks: 20}
		if err := d.Validate(); err != nil {
			t.Errorf("document_timeout %q: %v", in, err)
		}
		if got := d.DocumentTimeoutDuration(); got != want {
			t.Errorf("document_timeout %q = %v, want %v", in, got, want)
		}
	}
	if nilSettings.DocumentTimeoutDuration() != DefaultDocumentTimeout {
		t.Error("absent settings do not give the default document timeout")
	}
}

// Contributions are not strong evidence unless
// options.ai.contributions.strong_evidence says so.
func TestContributionsStrong(t *testing.T) {
	var none *AISettings
	if none.ContributionsStrong() || (&AISettings{}).ContributionsStrong() {
		t.Error("contributions are strong evidence by default")
	}

	c := &Config{Options: map[string]interface{}{"ai": map[string]interface{}{
		"contributions": map[string]interface{}{"strong_evidence": true}}}}
	if err := c.loadAISettings(c); err != nil {
		t.Fatal(err)
	}
	if !c.AI.ContributionsStrong() {
		t.Error("strong_evidence was not read")
	}

	c = &Config{Options: map[string]interface{}{"ai": map[string]interface{}{
		"contributions": map[string]interface{}{"strong": true}}}}
	if err := c.loadAISettings(c); err == nil {
		t.Error("an unknown contributions key was accepted")
	}
}
