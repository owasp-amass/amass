// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CompatibleModel supports OpenAI-compatible Chat Completions endpoints,
// including OpenAI and local vLLM, LM Studio, llama.cpp and Ollama's /v1
// API. Never log API keys or request bodies.
type CompatibleModel struct {
	// Endpoint must be the complete /v1/chat/completions URL.
	Endpoint  string
	ModelName string
	APIKey    string
	Client    *http.Client
	// MaxTokens, when positive, caps each reply: sent as max_tokens, or as
	// max_completion_tokens to a model that refuses max_tokens (OpenAI's
	// reasoning models).
	MaxTokens int
	// Temperature, when set, is sent with every request, unless the model
	// refuses it.
	Temperature *float64
	// Refused remembers the fields the model refused, so later requests
	// leave them out. NewCompatibleModel sets it; without it, each refused
	// request is retried without the field.
	Refused *Refused
}

var _ Model = CompatibleModel{}
var _ StructuredModel = CompatibleModel{}

// NewCompatibleModel returns a CompatibleModel that remembers the fields a
// model refuses across requests.
func NewCompatibleModel(endpoint, model, key string, client *http.Client) CompatibleModel {
	return CompatibleModel{Endpoint: endpoint, ModelName: model, APIKey: key, Client: client, Refused: &Refused{}}
}

// Generate implements Model.
func (m CompatibleModel) Generate(ctx context.Context, history []Message, specs []ToolSpec) (Response, error) {
	return m.complete(ctx, history, specs, nil)
}

// schemaName is what the API accepts as a response format name.
var schemaName = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// GenerateStructured implements StructuredModel with a json_schema response
// format. A server that refuses it is asked again with the prompt alone, and
// Go validation decides, as for providers without structured output.
func (m CompatibleModel) GenerateStructured(ctx context.Context, history []Message, schema JSONSchema) (Response, error) {
	if len(schema.Schema) == 0 {
		return Response{}, errors.New("structured generation requires a JSON schema")
	}
	name := schemaName.ReplaceAllString(schema.Name, "_")
	if name == "" {
		name = "result"
	}

	format := map[string]any{"type": "json_schema", "json_schema": map[string]any{
		"name": name, "description": schema.Description, "schema": schema.Schema, "strict": false}}
	return m.complete(ctx, history, nil, format)
}

// The request fields a model may refuse, each sent again without (or, for
// max_tokens, renamed to max_completion_tokens).
const (
	fieldMaxTokens      = "max_tokens"
	fieldTemperature    = "temperature"
	fieldResponseFormat = "response_format"
)

func (m CompatibleModel) complete(ctx context.Context, history []Message, specs []ToolSpec,
	format map[string]any) (Response, error) {
	var out Response
	if m.Endpoint == "" || m.ModelName == "" {
		return out, errors.New("model endpoint and name required")
	}

	msgs, err := compatibleMessages(history)
	if err != nil {
		return out, err
	}
	refused := map[string]bool{}
	for _, f := range []string{fieldMaxTokens, fieldTemperature, fieldResponseFormat} {
		refused[f] = m.Refused.Has(f)
	}

	headers := map[string]string{}
	if m.APIKey != "" {
		headers["Authorization"] = "Bearer " + m.APIKey
	}
	endpoint := strings.TrimSuffix(m.Endpoint, "/")
	for {
		request := map[string]any{"model": m.ModelName, "messages": msgs}
		var sent []string
		if m.MaxTokens > 0 {
			if refused[fieldMaxTokens] {
				request["max_completion_tokens"] = m.MaxTokens
			} else {
				request[fieldMaxTokens] = m.MaxTokens
				sent = append(sent, fieldMaxTokens)
			}
		}
		if m.Temperature != nil && !refused[fieldTemperature] {
			request[fieldTemperature] = *m.Temperature
			sent = append(sent, fieldTemperature)
		}
		if format != nil && !refused[fieldResponseFormat] {
			request[fieldResponseFormat] = format
			sent = append(sent, fieldResponseFormat, "json_schema")
		}
		if len(specs) > 0 {
			request["tools"] = compatibleTools(specs)
		}

		status, body, err := postJSON(ctx, m.Client, 90*time.Second, endpoint, headers, request)
		if err != nil {
			return out, err
		}
		if status >= 200 && status <= 299 {
			return compatibleReply(body)
		}

		// A model that refuses one of the optional fields is asked again
		// without it, and later requests leave it out.
		reason := apiError(body)
		field := refusedField(status, reason, sent...)
		if field == "json_schema" {
			field = fieldResponseFormat
		}
		if field == "" {
			return out, fmt.Errorf("compatible: HTTP status %d: %s", status, reason)
		}
		refused[field] = true
		m.Refused.add(field)
	}
}

func compatibleMessages(history []Message) ([]map[string]any, error) {
	var msgs []map[string]any
	for _, msg := range history {
		switch msg.Role {
		case "system", "user", "assistant", "tool":
		default:
			return nil, fmt.Errorf("unknown message role %q", msg.Role)
		}
		item := map[string]any{"role": msg.Role, "content": msg.Text}
		if msg.Role == "user" && len(msg.Images) > 0 {
			parts := []any{map[string]any{"type": "text", "text": msg.Text}}
			for _, img := range msg.Images {
				parts = append(parts, map[string]any{"type": "image_url", "image_url": map[string]any{
					"url": "data:" + img.MediaType + ";base64," + base64.StdEncoding.EncodeToString(img.Data)}})
			}
			item["content"] = parts
		}
		if msg.Role == "tool" {
			item["tool_call_id"] = msg.ToolCallID
		}
		if msg.Role == "assistant" && len(msg.Calls) > 0 {
			var calls []any
			for _, c := range msg.Calls {
				calls = append(calls, map[string]any{
					"id":       c.ID,
					"type":     "function",
					"function": map[string]any{"name": c.Name, "arguments": string(c.Arguments)},
				})
			}

			item["tool_calls"] = calls
			if msg.Text == "" {
				item["content"] = nil
			}
		}

		msgs = append(msgs, item)
	}
	return msgs, nil
}

func compatibleTools(specs []ToolSpec) []any {
	ts := make([]any, 0, len(specs))
	for _, s := range specs {
		ts = append(ts, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        s.Name,
				"description": s.Description,
				"parameters":  s.Parameters,
			},
		})
	}
	return ts
}

func compatibleReply(body []byte) (Response, error) {
	var out Response
	var payload struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return out, err
	}
	if len(payload.Choices) == 0 {
		return out, errors.New("model returned no choices")
	}

	choice := payload.Choices[0]
	if choice.Message.Content != nil {
		out.Text = *choice.Message.Content
	}
	for _, tc := range choice.Message.ToolCalls {
		if tc.ID == "" || tc.Function.Name == "" || !json.Valid([]byte(tc.Function.Arguments)) {
			return Response{}, errors.New("invalid model tool call")
		}

		out.Calls = append(out.Calls,
			Call{ID: tc.ID, Name: tc.Function.Name, Arguments: json.RawMessage(tc.Function.Arguments)})
	}

	out.InputTokens = payload.Usage.Prompt
	out.OutputTokens = payload.Usage.Completion
	if choice.FinishReason == "length" {
		return out, fmt.Errorf("compatible %w", ErrReplyLength)
	}
	return out, nil
}
