// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultOllamaContextTokens is large enough for the OAM catalog planner
// prompt (about 3,500 tokens) plus a structured reply. Ollama's own default
// context can be smaller and silently truncates long prompts.
const DefaultOllamaContextTokens = 8192

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
	// noThink is set after a model rejects the think field, so later requests
	// omit it. Shared by copies through the pointer.
	noThink *atomic.Bool
}

var _ Model = OllamaModel{}
var _ StructuredModel = OllamaModel{}

// NewOllamaModel returns an OllamaModel with thinking off and defaults set.
func NewOllamaModel(endpoint, model string, client *http.Client) OllamaModel {
	return OllamaModel{Endpoint: endpoint, ModelName: model, Client: client, noThink: &atomic.Bool{}}
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
		if strings.Contains(lower, "format") || strings.Contains(lower, "schema") || strings.Contains(lower, "grammar") {
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
	sendThink := m.noThink == nil || !m.noThink.Load()
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
	body, status, err := m.post(ctx, url, request)
	if err != nil {
		return out, err
	}
	// Some models reject the think field outright. Retry once without it and
	// remember, rather than failing every request for non-reasoning models.
	if status == http.StatusBadRequest && sendThink && !m.Think && strings.Contains(strings.ToLower(string(body)), "think") {
		if m.noThink != nil {
			m.noThink.Store(true)
		}
		delete(request, "think")
		body, status, err = m.post(ctx, url, request)
		if err != nil {
			return out, err
		}
	}
	if status < 200 || status > 299 {
		return out, fmt.Errorf("ollama HTTP status %d: %s", status, ollamaError(body))
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
		out.Calls = append(out.Calls, Call{ID: fmt.Sprintf("ollama-call-%d", i+1), Name: tc.Function.Name, Arguments: args})
	}
	out.InputTokens = payload.PromptEvalCount
	out.OutputTokens = payload.EvalCount
	if payload.DoneReason == "length" {
		return out, fmt.Errorf("ollama reply hit the %v-token limit (num_ctx/num_predict); raise -context-tokens or -max-tokens", options["num_ctx"])
	}
	return out, nil
}

func (m OllamaModel) post(ctx context.Context, url string, request map[string]any) ([]byte, int, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

// ollamaError extracts Ollama's {"error": "..."} message, bounded in length.
func ollamaError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}
