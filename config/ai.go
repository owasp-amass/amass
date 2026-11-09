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
}

// ResolveAISettings applies AMASS_AI_* environment overrides without
// mutating the global Amass config. Empty env strings are intentional values.
func ResolveAISettings(base AISettings, lookup func(string) (string, bool)) (AISettings, error) {
	c := base
	stringsEnv := []struct {
		key    string
		target *string
	}{
		{"AMASS_AI_PROVIDER", &c.Provider},
		{"AMASS_AI_ENDPOINT", &c.Endpoint},
		{"AMASS_AI_MODEL", &c.Model},
		{"AMASS_AI_API_KEY_ENV", &c.APIKeyEnv},
		{"AMASS_AI_MODEL_TIMEOUT", &c.ModelTimeout},
		{"AMASS_AI_INVESTIGATION_TIMEOUT", &c.InvestigationTimeout},
		{"AMASS_AI_CLASSIFIER_MODEL", &c.ClassifierModel},
		{"AMASS_AI_CLASSIFIER_ENDPOINT", &c.ClassifierEndpoint},
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
		{"AMASS_AI_ALLOW_HTTP", &c.AllowHTTP},
		{"AMASS_AI_CLASSIFIER_REVIEW", &c.ClassifierReview},
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
	ints := []struct {
		key    string
		target *int
	}{
		{"AMASS_AI_DEPTH", &c.MaxDepth},
		{"AMASS_AI_MAX_MATCHES", &c.MaxMatches},
		{"AMASS_AI_MAX_PATHS_PER_ASSET", &c.MaxPathsPerAsset},
		{"AMASS_AI_MAX_EXPANSIONS", &c.MaxExpansions},
		{"AMASS_AI_GUIDANCE_ROUNDS", &c.GuidanceRounds},
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
	return c, nil
}
