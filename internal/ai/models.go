// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// ModelSettings configures one model client.
type ModelSettings struct {
	Provider, Endpoint, Model, APIKey string
	AllowHTTP                         bool
	Timeout                           time.Duration
	MaxTokens, ContextTokens          int
	Temperature                       *float64
	Think                             bool
}

// NewModel builds the configured model client and checks its endpoint.
func NewModel(s ModelSettings) (llm.Model, error) {
	endpoint := s.Endpoint
	var provider llm.Model
	switch s.Provider {
	case "ollama":
		if endpoint == "" {
			endpoint = "http://127.0.0.1:11434"
		}
		if _, err := llm.OllamaChatURL(endpoint); err != nil {
			return nil, err
		}

		m := llm.NewOllamaModel(endpoint, s.Model, &http.Client{Timeout: s.Timeout})
		m.Think, m.ContextTokens, m.MaxTokens, m.Temperature = s.Think, s.ContextTokens, s.MaxTokens, s.Temperature
		provider = m
	case "compatible":
		if endpoint == "" {
			endpoint = "http://127.0.0.1:11434/v1/chat/completions"
		}

		m := llm.NewCompatibleModel(endpoint, s.Model, s.APIKey, &http.Client{Timeout: s.Timeout})
		m.MaxTokens, m.Temperature = s.MaxTokens, s.Temperature
		provider = m
	case "anthropic":
		if endpoint == "" {
			endpoint = "https://api.anthropic.com/v1/messages"
		}

		m := llm.NewAnthropicModel(endpoint, s.Model, s.APIKey, &http.Client{Timeout: s.Timeout})
		m.MaxTokens, m.Temperature = s.MaxTokens, s.Temperature
		provider = m
	default:
		return nil, fmt.Errorf("unknown model provider %q", s.Provider)
	}
	if err := ValidateModelEndpoint(endpoint, s.AllowHTTP); err != nil {
		return nil, err
	}

	return provider, nil
}

// ValidateModelEndpoint prevents accidental plaintext transmission of graph
// data: HTTPS, loopback HTTP, or HTTP explicitly allowed for a trusted
// internal endpoint.
func ValidateModelEndpoint(endpoint string, allowHTTP bool) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid inference endpoint: %w", err)
	}
	if u.User != nil || u.Host == "" || u.Hostname() == "" || u.Fragment != "" {
		return errors.New("inference endpoint must have a hostname and no URL credentials or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" {
		return errors.New("inference endpoint must use HTTPS or explicitly permitted HTTP")
	}
	if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" {
		return nil
	}
	if !allowHTTP {
		return errors.New("remote HTTP inference requires explicit -allow-http or AMASS_LLM_ALLOW_HTTP=true for a trusted internal endpoint")
	}

	return nil
}

// DefaultDocumentContextTokens is the document model's Ollama context window:
// room for a chunk of a document, the instructions and the reply. It is the
// size every Ollama caller asks for, so the document model and the main model
// share one loaded model when they are the same.
const DefaultDocumentContextTokens = llm.DefaultOllamaContextTokens

// DefaultDocumentReplyTokens caps one document model reply when
// options.ai.documents.max_tokens is not set: room for many findings from one
// chunk, far short of a context window filled by a model repeating itself.
const DefaultDocumentReplyTokens = 4096

// DefaultDocumentModelTimeout bounds one document model request when
// options.ai.documents.model_timeout is not set.
const DefaultDocumentModelTimeout = 3 * time.Minute

// DocumentModel builds the model the user named in options.ai.documents, with its
// name for the statements it reads and its per-request timeout. There is no
// fallback to the main model: without options.ai.documents no model reads documents.
func DocumentModel(d *config.DocumentModelSettings) (llm.Model, string, time.Duration, error) {
	if d == nil || !d.Enabled {
		return nil, "", 0, errors.New("no document model is configured: enable options.ai.documents in the config " +
			"(the main model is never used to read documents)")
	}
	if err := d.Validate(); err != nil {
		return nil, "", 0, err
	}

	timeout := DefaultDocumentModelTimeout
	if d.ModelTimeout != "" {
		v, err := time.ParseDuration(d.ModelTimeout)
		if err != nil {
			return nil, "", 0, err
		}
		timeout = v
	}

	var key string
	if d.APIKeyEnv != "" {
		// a key pasted with a trailing newline or space is refused as invalid
		key = strings.TrimSpace(os.Getenv(d.APIKeyEnv))
	}
	provider := strings.ToLower(strings.TrimSpace(d.Provider))
	zero := 0.0
	contextTokens := d.ContextTokens
	if contextTokens == 0 {
		contextTokens = DefaultDocumentContextTokens
	}
	maxTokens := d.MaxTokens
	if maxTokens == 0 {
		maxTokens = DefaultDocumentReplyTokens
	}
	m, err := NewModel(ModelSettings{Provider: provider, Endpoint: d.Endpoint, Model: d.Model,
		APIKey: key, AllowHTTP: d.AllowHTTP, Timeout: timeout, Temperature: &zero, ContextTokens: contextTokens,
		MaxTokens: maxTokens})
	if err != nil {
		return nil, "", 0, fmt.Errorf("options.ai.documents: %w", err)
	}
	return m, provider + "/" + d.Model, timeout, nil
}
