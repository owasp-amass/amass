// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"errors"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// DefaultMainModelTimeout bounds one main model request when model_timeout
// is not set.
const DefaultMainModelTimeout = 4 * time.Minute

// MainModel builds the main model from resolved settings
// (config.ResolveAISettings). The API key is read from the variable
// APIKeyEnv names, or from AMASS_LLM_API_KEY. It returns ok false, and no
// error, when no model is configured.
func MainModel(s config.AISettings, lookup func(string) (string, bool)) (llm.Model, time.Duration, bool, error) {
	if strings.TrimSpace(s.Model) == "" || strings.TrimSpace(s.Endpoint) == "" {
		return nil, 0, false, nil
	}

	timeout := DefaultMainModelTimeout
	if s.ModelTimeout != "" {
		var err error
		if timeout, err = time.ParseDuration(s.ModelTimeout); err != nil {
			return nil, 0, false, err
		}
	}
	keyEnv := s.APIKeyEnv
	if keyEnv == "" {
		keyEnv = "AMASS_LLM_API_KEY"
	}
	key, _ := lookup(keyEnv)
	key = strings.TrimSpace(key)
	if s.Provider == "anthropic" && key == "" {
		return nil, 0, false, errors.New("the Anthropic provider requires an API key")
	}

	m, err := NewModel(ModelSettings{Provider: s.Provider, Endpoint: s.Endpoint, Model: s.Model, APIKey: key,
		AllowHTTP: s.AllowHTTP, Timeout: timeout, ContextTokens: s.ContextTokens, Think: s.Think})
	if err != nil {
		return nil, 0, false, err
	}
	return m, timeout, true, nil
}
