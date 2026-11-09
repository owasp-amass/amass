// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// maxQueryFileBytes bounds a -query file; real queries are a few KB.
const maxQueryFileBytes = 1 << 20

// newProvider builds the configured model client and checks its endpoint.
func newProvider(providerName, endpoint, modelName, apiKey string, allowHTTP bool, timeout time.Duration, maxTokens int, temperature *float64) (ai.Model, error) {
	var provider ai.Model
	switch providerName {
	case "compatible":
		if endpoint == "" {
			endpoint = "http://127.0.0.1:11434/v1/chat/completions"
		}
		provider = ai.CompatibleModel{Endpoint: endpoint, ModelName: modelName, APIKey: apiKey, Client: &http.Client{Timeout: timeout}, MaxTokens: maxTokens, Temperature: temperature}
	case "anthropic":
		if endpoint == "" {
			endpoint = "https://api.anthropic.com/v1/messages"
		}
		provider = ai.AnthropicModel{Endpoint: endpoint, ModelName: modelName, APIKey: apiKey, Client: &http.Client{Timeout: timeout}, MaxTokens: maxTokens, Temperature: temperature}
	default:
		return nil, fmt.Errorf("unknown model provider %q", providerName)
	}
	if err := validateModelEndpoint(endpoint, allowHTTP); err != nil {
		return nil, err
	}
	return provider, nil
}

// readQuery loads a Query from path, or from stdin when path is "-". Unknown
// fields are rejected so a mistyped key cannot silently widen a query.
func readQuery(path string, stdin io.Reader) (ai.Query, error) {
	var q ai.Query
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return q, fmt.Errorf("open query: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxQueryFileBytes+1))
	if err != nil {
		return q, fmt.Errorf("read query: %w", err)
	}
	if len(raw) > maxQueryFileBytes {
		return q, errors.New("query file exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return q, fmt.Errorf("decode query: %w", err)
	}
	if dec.More() {
		return q, errors.New("query file must hold exactly one JSON object")
	}
	return q, nil
}

func writeJSON(out io.Writer, v any) error {
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(pretty))
	return err
}

// writeInvestigation prints an investigation as json, text or mermaid.
func writeInvestigation(out io.Writer, format string, result ai.Investigation) error {
	switch format {
	case "text":
		_, err := fmt.Fprintln(out, result.Answer)
		return err
	case "mermaid":
		if result.Diagram == "" {
			return fmt.Errorf("investigation did not produce a diagram: %s", result.Answer)
		}
		_, err := fmt.Fprint(out, result.Diagram)
		return err
	case "json":
		return writeJSON(out, result)
	default:
		return errors.New("-format must be json, text, or mermaid")
	}
}
