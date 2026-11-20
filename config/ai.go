// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AISettings is an opt-in set of model and investigation defaults. No model
// requests, network listeners, or collection tasks start just because this
// section is present. CLI flags override env vars, which override this YAML.
type AISettings struct {
	Provider             string `yaml:"provider,omitempty" json:"provider,omitempty"`
	Endpoint             string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Model                string `yaml:"model,omitempty" json:"model,omitempty"`
	APIKeyEnv            string `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	AllowHTTP            bool   `yaml:"allow_http,omitempty" json:"allow_http,omitempty"`
	ModelTimeout         string `yaml:"model_timeout,omitempty" json:"model_timeout,omitempty"`
	InvestigationTimeout string `yaml:"investigation_timeout,omitempty" json:"investigation_timeout,omitempty"`
	ClassifierModel      string `yaml:"classifier_model,omitempty" json:"classifier_model,omitempty"`
	ClassifierEndpoint   string `yaml:"classifier_endpoint,omitempty" json:"classifier_endpoint,omitempty"`
	ClassifierReview     bool   `yaml:"classifier_review,omitempty" json:"classifier_review,omitempty"`
	MaxDepth             int    `yaml:"depth,omitempty" json:"depth,omitempty"`
	MaxMatches           int    `yaml:"max_matches,omitempty" json:"max_matches,omitempty"`
	MaxPathsPerAsset     int    `yaml:"max_paths_per_asset,omitempty" json:"max_paths_per_asset,omitempty"`
	MaxExpansions        int    `yaml:"max_expansions,omitempty" json:"max_expansions,omitempty"`
	GuidanceRounds       int    `yaml:"guidance_rounds,omitempty" json:"guidance_rounds,omitempty"`
	// MaxTokens caps each model reply; 0 keeps the provider default.
	MaxTokens int `yaml:"max_tokens,omitempty" json:"max_tokens,omitempty"`
	// Temperature is a decimal 0..2; empty keeps the provider default.
	Temperature string `yaml:"temperature,omitempty" json:"temperature,omitempty"`
	// ContextTokens sets the Ollama context window; 0 keeps the default.
	ContextTokens int `yaml:"context_tokens,omitempty" json:"context_tokens,omitempty"`
	// Think enables an Ollama reasoning model's thinking phase (off by default).
	Think bool `yaml:"think,omitempty" json:"think,omitempty"`
	// Attribution controls ownership attribution during enumeration: "auto"
	// (the default) writes strong proposals and journals the rest, "journal"
	// only journals them, and "off" turns it off. It needs no model.
	Attribution string `yaml:"attribution,omitempty" json:"attribution,omitempty"`
	// Journal is the review journal path; empty uses review.jsonl in the
	// Amass output directory.
	Journal string `yaml:"journal,omitempty" json:"journal,omitempty"`
	// AnnounceDecisions controls whether the classifier's applied decisions and
	// new proposals are announced proactively (the end-of-run summary and the
	// assistant push). Nil means the default — on whenever attribution is not
	// off; set false to silence the announcements without changing attribution.
	AnnounceDecisions *bool `yaml:"announce_decisions,omitempty" json:"announce_decisions,omitempty"`
}

// Attribution modes.
const (
	AttributionAuto    = "auto"
	AttributionJournal = "journal"
	AttributionOff     = "off"
)

// ResolveAISettings applies AMASS_AI_* environment overrides without
// mutating the global Amass config. Empty env strings are intentional values.
func ResolveAISettings(base AISettings, lookup func(string) (string, bool)) (AISettings, error) {
	c := base
	stringsEnv := []struct {
		key    string
		target *string
	}{
		{"AMASS_LLM_PROVIDER", &c.Provider},
		{"AMASS_LLM_ENDPOINT", &c.Endpoint},
		{"AMASS_LLM_MODEL", &c.Model},
		{"AMASS_LLM_API_KEY_ENV", &c.APIKeyEnv},
		{"AMASS_LLM_MODEL_TIMEOUT", &c.ModelTimeout},
		{"AMASS_LLM_INVESTIGATION_TIMEOUT", &c.InvestigationTimeout},
		{"AMASS_LLM_TEMPERATURE", &c.Temperature},
		{"AMASS_CLASSIFIER_MODEL", &c.ClassifierModel},
		{"AMASS_CLASSIFIER_ENDPOINT", &c.ClassifierEndpoint},
		{"AMASS_ATTRIBUTION", &c.Attribution},
		{"AMASS_REVIEW_JOURNAL", &c.Journal},
	}
	for _, pair := range stringsEnv {
		if value, ok := lookup(pair.key); ok {
			*pair.target = value
		}
	}

	bools := []struct {
		key    string
		target *bool
	}{
		{"AMASS_LLM_ALLOW_HTTP", &c.AllowHTTP},
		{"AMASS_CLASSIFIER_REVIEW", &c.ClassifierReview},
		{"AMASS_LLM_THINK", &c.Think},
	}
	for _, pair := range bools {
		if raw, ok := lookup(pair.key); ok {
			value, err := strconv.ParseBool(strings.TrimSpace(raw))
			if err != nil {
				return c, fmt.Errorf("%s: invalid boolean", pair.key)
			}

			*pair.target = value
		}
	}

	if raw, ok := lookup("AMASS_AI_ANNOUNCE_DECISIONS"); ok {
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return c, fmt.Errorf("AMASS_AI_ANNOUNCE_DECISIONS: invalid boolean")
		}
		c.AnnounceDecisions = &value
	}

	ints := []struct {
		key    string
		target *int
	}{
		{"AMASS_LLM_DEPTH", &c.MaxDepth},
		{"AMASS_LLM_MAX_MATCHES", &c.MaxMatches},
		{"AMASS_LLM_MAX_PATHS_PER_ASSET", &c.MaxPathsPerAsset},
		{"AMASS_LLM_MAX_EXPANSIONS", &c.MaxExpansions},
		{"AMASS_LLM_GUIDANCE_ROUNDS", &c.GuidanceRounds},
		{"AMASS_LLM_MAX_TOKENS", &c.MaxTokens},
		{"AMASS_LLM_CONTEXT_TOKENS", &c.ContextTokens},
	}
	for _, pair := range ints {
		if raw, ok := lookup(pair.key); ok {
			value, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || value < 0 {
				return c, fmt.Errorf("%s: invalid nonnegative integer", pair.key)
			}

			*pair.target = value
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Attribution)) {
	case "", AttributionAuto, AttributionJournal, AttributionOff:
	default:
		return c, fmt.Errorf("attribution must be auto, journal or off")
	}
	if c.ModelTimeout != "" {
		v, err := time.ParseDuration(c.ModelTimeout)
		if err != nil || v < 5*time.Second || v > 15*time.Minute {
			return c, fmt.Errorf("model timeout must be 5s..15m")
		}
	}
	if c.InvestigationTimeout != "" {
		v, err := time.ParseDuration(c.InvestigationTimeout)
		if err != nil || v < 5*time.Second || v > 30*time.Minute {
			return c, fmt.Errorf("investigation timeout must be 5s..30m")
		}
	}
	if c.MaxPathsPerAsset > 8 {
		return c, fmt.Errorf("AI max_paths_per_asset must be 0..8")
	}
	if c.GuidanceRounds > 3 {
		return c, fmt.Errorf("AI guidance_rounds must be 0..3")
	}
	if c.ContextTokens != 0 && (c.ContextTokens < 2048 || c.ContextTokens > 262144) {
		return c, fmt.Errorf("AI context_tokens must be 0 or 2048..262144")
	}
	if c.MaxTokens > 128000 {
		return c, fmt.Errorf("AI max_tokens must be 0..128000")
	}
	if _, err := ParseAITemperature(c.Temperature); err != nil {
		return c, err
	}

	return c, nil
}

// ParseAITemperature returns nil for an empty value (provider default) or the
// parsed temperature, which must be between 0 and 2.
func ParseAITemperature(raw string) (*float64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 0 || v > 2 {
		return nil, fmt.Errorf("AI temperature must be a number from 0 to 2")
	}

	return &v, nil
}
