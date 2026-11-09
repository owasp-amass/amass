// SPDX-License-Identifier: Apache-2.0
package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAISettingsYAMLAndEnvironmentPrecedence(t *testing.T) {
	raw := `ai:
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
`
	c := NewConfig()
	if err := yaml.Unmarshal([]byte(raw), c); err != nil {
		t.Fatal(err)
	}
	if c.AI == nil || c.AI.Model != "qwen3:8b" || c.AI.MaxDepth != 8 || !c.AI.AllowHTTP {
		t.Fatalf("YAML section failed to decode: %+v", c.AI)
	}
	env := map[string]string{
		"AMASS_AI_MODEL":             "qwen3:14b",
		"AMASS_AI_DEPTH":             "12",
		"AMASS_AI_CLASSIFIER_REVIEW": "true",
		"AMASS_AI_MODEL_TIMEOUT":     "6m",
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
		{"AMASS_AI_ALLOW_HTTP", "maybe"},
		{"AMASS_AI_MODEL_TIMEOUT", "zero"},
		{"AMASS_AI_INVESTIGATION_TIMEOUT", "0s"},
		{"AMASS_AI_MAX_PATHS_PER_ASSET", "-1"},
		{"AMASS_AI_GUIDANCE_ROUNDS", "4"},
		{"AMASS_AI_DEPTH", "x"},
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
			if !strings.Contains(err.Error(), "AI") && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), tc.key) {
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
