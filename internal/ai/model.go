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
	"time"
)

type Message struct {
	Role       string `json:"role"`
	Text       string `json:"text,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Calls      []Call `json:"calls,omitempty"`
}
type Call struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}
type Response struct {
	Text         string
	Calls        []Call
	InputTokens  int
	OutputTokens int
}
type Model interface {
	Generate(context.Context, []Message, []ToolSpec) (Response, error)
}

// CompatibleModel supports OpenAI-compatible Chat Completions endpoints, including
// local Ollama/vLLM/LM Studio. Never log API keys or request bodies.
type CompatibleModel struct {
	Endpoint  string
	ModelName string
	APIKey    string
	Client    *http.Client
}

func (m CompatibleModel) Generate(ctx context.Context, history []Message, specs []ToolSpec) (Response, error) {
	var out Response
	if m.Endpoint == "" || m.ModelName == "" {
		return out, errors.New("model endpoint and name required")
	}
	var msgs []map[string]any
	for _, msg := range history {
		item := map[string]any{"role": msg.Role, "content": msg.Text}
		if msg.Role == "tool" {
			item["tool_call_id"] = msg.ToolCallID
		}
		if msg.Role == "assistant" && len(msg.Calls) > 0 {
			var calls []any
			for _, c := range msg.Calls {
				calls = append(calls, map[string]any{"id": c.ID, "type": "function", "function": map[string]any{"name": c.Name, "arguments": string(c.Arguments)}})
			}
			item["tool_calls"] = calls
			if msg.Text == "" {
				item["content"] = nil
			}
		}
		msgs = append(msgs, item)
	}
	request := map[string]any{"model": m.ModelName, "messages": msgs}
	if len(specs) > 0 {
		ts := make([]any, 0, len(specs))
		for _, s := range specs {
			ts = append(ts, map[string]any{"type": "function", "function": map[string]any{"name": s.Name, "description": s.Description, "parameters": s.Parameters}})
		}
		request["tools"] = ts
	}
	data, err := json.Marshal(request)
	if err != nil {
		return out, err
	}
	endpoint := strings.TrimSuffix(m.Endpoint, "/")
	// Endpoint must be the complete /v1/chat/completions URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	if m.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.APIKey)
	}
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return out, fmt.Errorf("model HTTP status %d", resp.StatusCode)
	}
	var payload struct {
		Choices []struct {
			Message struct {
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
	c := payload.Choices[0].Message
	if c.Content != nil {
		out.Text = *c.Content
	}
	for _, tc := range c.ToolCalls {
		if tc.ID == "" || tc.Function.Name == "" || !json.Valid([]byte(tc.Function.Arguments)) {
			return Response{}, errors.New("invalid model tool call")
		}
		out.Calls = append(out.Calls, Call{ID: tc.ID, Name: tc.Function.Name, Arguments: json.RawMessage(tc.Function.Arguments)})
	}
	out.InputTokens = payload.Usage.Prompt
	out.OutputTokens = payload.Usage.Completion
	return out, nil
}
