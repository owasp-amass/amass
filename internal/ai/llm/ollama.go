// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultOllamaContextTokens is large enough for the OAM catalog planner
// prompt (about 3,500 tokens) plus a structured reply, and for a chunk of a
// document. Ollama's own default context can be smaller and silently
// truncates long prompts. Ollama reloads a model whenever a request asks for
// a different context size, so every caller uses this one size and a model
// loaded for one is kept for the next.
const DefaultOllamaContextTokens = 16384

// DefaultOllamaKeepAlive keeps the model loaded between the separate CLI
// runs of an interactive session, avoiding a reload on every question.
const DefaultOllamaKeepAlive = "30m"

// OllamaModel calls Ollama's native /api/chat endpoint. Unlike the
// OpenAI-compatible endpoint, it can turn a reasoning model's thinking off,
// set the context window and constrain replies to a JSON schema.
type OllamaModel struct {
	// Endpoint is the Ollama base URL (http://host:11434) or the full
	// /api/chat URL. OpenAI-compatible /v1 URLs are rejected.
	Endpoint  string
	ModelName string
	Client    *http.Client
	// Think enables the model's reasoning phase. Off by default: thinking
	// multiplies latency on CPU-only hosts and is not needed for planning.
	Think bool
	// ContextTokens sets options.num_ctx; 0 selects DefaultOllamaContextTokens.
	ContextTokens int
	// MaxTokens, when positive, sets options.num_predict.
	MaxTokens   int
	Temperature *float64
	// KeepAlive overrides DefaultOllamaKeepAlive (an Ollama duration string).
	KeepAlive string
	// refused remembers the fields the model refused, such as think, so later
	// requests omit them. Shared by copies through the pointer.
	refused *Refused
}

// ErrReplyLength is a reply cut off at the token limit (num_predict or
// num_ctx): its text is incomplete.
var ErrReplyLength = errors.New("reply hit the token limit")

var _ Model = OllamaModel{}
var _ StructuredModel = OllamaModel{}

// NewOllamaModel returns an OllamaModel with thinking off and defaults set.
func NewOllamaModel(endpoint, model string, client *http.Client) OllamaModel {
	return OllamaModel{Endpoint: endpoint, ModelName: model, Client: client, refused: &Refused{}}
}

// OllamaChatURL normalises an Ollama endpoint to its /api/chat URL.
func OllamaChatURL(endpoint string) (string, error) {
	e := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if e == "" {
		return "", errors.New("ollama endpoint required")
	}
	if strings.Contains(e, "/v1/") || strings.HasSuffix(e, "/v1") {
		return "", errors.New("the ollama provider uses the native API: set the endpoint to the Ollama base URL (for example http://ollama:11434), or use provider compatible for /v1 URLs")
	}
	if strings.HasSuffix(e, "/api/chat") {
		return e, nil
	}

	return e + "/api/chat", nil
}

type ollamaToolCall struct {
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
}

// Generate implements Model.
func (m OllamaModel) Generate(ctx context.Context, history []Message, specs []ToolSpec) (Response, error) {
	return m.chat(ctx, history, specs, nil)
}

// GenerateStructured implements StructuredModel using Ollama's format field.
func (m OllamaModel) GenerateStructured(ctx context.Context, history []Message, schema JSONSchema) (Response, error) {
	if len(schema.Schema) == 0 {
		return Response{}, errors.New("structured generation requires a JSON schema")
	}

	resp, err := m.chat(ctx, history, nil, schema.Schema)
	if err != nil && strings.Contains(err.Error(), "ollama HTTP status 400") {
		// An Ollama build that cannot compile this schema into a grammar
		// should not block planning: ask again without the constraint and let
		// Go validation decide, as for providers without structured output.
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "format") || strings.Contains(lower, "schema") || strings.Contains(lower,
			"grammar") {
			return m.chat(ctx, history, nil, nil)
		}
	}

	return resp, err
}

func (m OllamaModel) chat(ctx context.Context, history []Message, specs []ToolSpec, format map[string]any) (Response, error) {
	var out Response
	if m.ModelName == "" {
		return out, errors.New("ollama model name required")
	}

	url, err := OllamaChatURL(m.Endpoint)
	if err != nil {
		return out, err
	}

	// Ollama tool calls carry no IDs; map each tool result back to the name
	// of the call it answers so the model can tell results apart.
	callNames := map[string]string{}
	msgs := make([]ollamaMessage, 0, len(history))
	for _, msg := range history {
		switch msg.Role {
		case "system", "user":
			msgs = append(msgs, ollamaMessage{Role: msg.Role, Content: msg.Text})
		case "assistant":
			om := ollamaMessage{Role: "assistant", Content: msg.Text}
			for _, c := range msg.Calls {
				var tc ollamaToolCall
				tc.Function.Name = c.Name
				tc.Function.Arguments = c.Arguments
				om.ToolCalls = append(om.ToolCalls, tc)
				callNames[c.ID] = c.Name
			}

			msgs = append(msgs, om)
		case "tool":
			msgs = append(msgs, ollamaMessage{Role: "tool", Content: msg.Text, ToolName: callNames[msg.ToolCallID]})
		default:
			return out, fmt.Errorf("unknown message role %q", msg.Role)
		}
	}

	options := map[string]any{"num_ctx": m.ContextTokens}
	if m.ContextTokens == 0 {
		options["num_ctx"] = DefaultOllamaContextTokens
	}
	if m.MaxTokens > 0 {
		options["num_predict"] = m.MaxTokens
	}
	if m.Temperature != nil {
		options["temperature"] = *m.Temperature
	}

	keepAlive := m.KeepAlive
	if keepAlive == "" {
		keepAlive = DefaultOllamaKeepAlive
	}

	request := map[string]any{"model": m.ModelName, "messages": msgs, "stream": false,
		"options": options, "keep_alive": keepAlive}
	sendThink := !m.refused.Has("think")
	if sendThink {
		request["think"] = m.Think
	}
	if len(specs) > 0 {
		tools := make([]any, 0, len(specs))
		for _, s := range specs {
			tools = append(tools, map[string]any{"type": "function", "function": map[string]any{
				"name": s.Name, "description": s.Description, "parameters": s.Parameters}})
		}

		request["tools"] = tools
	}
	if format != nil {
		request["format"] = format
	}

	status, body, err := postJSON(ctx, m.Client, 4*time.Minute, url, nil, request)
	if err != nil {
		return out, err
	}
	// Some models reject the think field outright. Retry once without it and
	// remember, rather than failing every request for non-reasoning models.
	if sendThink && !m.Think && refusedField(status, apiError(body), "think") != "" {
		m.refused.add("think")
		delete(request, "think")
		status, body, err = postJSON(ctx, m.Client, 4*time.Minute, url, nil, request)
		if err != nil {
			return out, err
		}
	}
	if status < 200 || status > 299 {
		return out, fmt.Errorf("ollama HTTP status %d: %s", status, apiError(body))
	}

	var payload struct {
		Message struct {
			Content   string           `json:"content"`
			ToolCalls []ollamaToolCall `json:"tool_calls"`
		} `json:"message"`
		Done            bool   `json:"done"`
		DoneReason      string `json:"done_reason"`
		PromptEvalCount int    `json:"prompt_eval_count"`
		EvalCount       int    `json:"eval_count"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return out, fmt.Errorf("decode ollama reply: %w", err)
	}

	out.Text = payload.Message.Content
	for i, tc := range payload.Message.ToolCalls {
		args := tc.Function.Arguments
		if len(args) == 0 || string(args) == "null" {
			args = json.RawMessage(`{}`)
		}
		if tc.Function.Name == "" || !json.Valid(args) {
			return Response{}, errors.New("invalid ollama tool call")
		}

		out.Calls = append(out.Calls, Call{ID: fmt.Sprintf("ollama-call-%d",
			i+1), Name: tc.Function.Name, Arguments: args})
	}

	out.InputTokens = payload.PromptEvalCount
	out.OutputTokens = payload.EvalCount
	if payload.DoneReason == "length" {
		return out, fmt.Errorf("ollama %w (num_ctx %v, num_predict %v); raise -context-tokens or -max-tokens",
			ErrReplyLength, options["num_ctx"], options["num_predict"])
	}

	return out, nil
}

// ContextLength returns the context window the model was trained with, from
// Ollama's /api/show (model_info "<architecture>.context_length"), or 0 when
// Ollama does not report one. A num_ctx above it gains nothing, and a prompt
// that needs more than it is read poorly.
func (m OllamaModel) ContextLength(ctx context.Context) (int, error) {
	chat, err := OllamaChatURL(m.Endpoint)
	if err != nil {
		return 0, err
	}
	url := strings.TrimSuffix(chat, "/api/chat") + "/api/show"

	status, body, err := postJSON(ctx, m.Client, 30*time.Second, url, nil, map[string]any{"model": m.ModelName})
	if err != nil {
		return 0, err
	}
	if status < 200 || status > 299 {
		return 0, fmt.Errorf("ollama HTTP status %d: %s", status, apiError(body))
	}

	var show struct {
		ModelInfo map[string]any `json:"model_info"`
	}
	if err := json.Unmarshal(body, &show); err != nil {
		return 0, fmt.Errorf("decode ollama model details: %w", err)
	}
	for k, v := range show.ModelInfo {
		if n, ok := v.(float64); ok && strings.HasSuffix(k, ".context_length") && n > 0 {
			return int(n), nil
		}
	}
	return 0, nil
}
