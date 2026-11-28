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
	"strings"
	"time"
)

// AnthropicModel is a native Messages API implementation of the common Model.
type AnthropicModel struct {
	Endpoint  string
	ModelName string
	APIKey    string
	Client    *http.Client
	// MaxTokens caps each reply; 0 selects DefaultAnthropicMaxTokens.
	MaxTokens int
	// Temperature, when set, is sent with every request. Planning and
	// path selection are most reproducible at 0.
	Temperature *float64
	// DisablePromptCache turns off cache_control on the system prompt.
	// Investigations resend a large, fixed OAM catalog prompt, so caching
	// is on by default; prompts below the provider minimum are not cached.
	DisablePromptCache bool
	// forceTool, when set, requires the model to call that tool (used by
	// GenerateStructured).
	forceTool string
	// Refused remembers the fields the model refused, such as temperature
	// (newer models fix their sampling), so later requests leave them out.
	// NewAnthropicModel sets it; without it, each refused request is retried
	// once without the field.
	Refused *Refused
}

// NewAnthropicModel returns an AnthropicModel that remembers the fields a
// model refuses across requests.
func NewAnthropicModel(endpoint, model, key string, client *http.Client) AnthropicModel {
	return AnthropicModel{Endpoint: endpoint, ModelName: model, APIKey: key, Client: client, Refused: &Refused{}}
}

// DefaultAnthropicMaxTokens is the reply budget when MaxTokens is unset.
const DefaultAnthropicMaxTokens = 4096

func (m AnthropicModel) Generate(ctx context.Context, history []Message, specs []ToolSpec) (Response, error) {
	if m.Refused.Has("temperature") {
		m.Temperature = nil
	}
	if m.Refused.Has("tool_choice") {
		m.forceTool = ""
	}
	var out Response
	if m.ModelName == "" || m.APIKey == "" {
		return out, errors.New("the Anthropic provider requires a model and API key")
	}

	endpoint := m.Endpoint
	if endpoint == "" {
		endpoint = "https://api.anthropic.com/v1/messages"
	}

	var messages []map[string]any
	var system string
	for _, msg := range history {
		if msg.Role == "system" {
			system += msg.Text + "\n"
			continue
		}
		if msg.Role == "tool" {
			messages = append(messages,
				map[string]any{
					"role": "user",
					"content": []any{
						map[string]any{"type": "tool_result", "tool_use_id": msg.ToolCallID, "content": msg.Text},
					},
				})
			continue
		}
		if msg.Role == "assistant" && len(msg.Calls) > 0 {
			blocks := []any{}
			if msg.Text != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": msg.Text})
			}
			for _, call := range msg.Calls {
				blocks = append(blocks,
					map[string]any{
						"type":  "tool_use",
						"id":    call.ID,
						"name":  call.Name,
						"input": json.RawMessage(call.Arguments),
					})
			}

			messages = append(messages, map[string]any{"role": "assistant", "content": blocks})
			continue
		}
		if msg.Role != "user" && msg.Role != "assistant" {
			return out, fmt.Errorf("unknown message role %q", msg.Role)
		}

		if msg.Role == "user" && len(msg.Images) > 0 {
			blocks := []any{}
			for _, img := range msg.Images {
				blocks = append(blocks, map[string]any{"type": "image", "source": map[string]any{
					"type": "base64", "media_type": img.MediaType,
					"data": base64.StdEncoding.EncodeToString(img.Data)}})
			}
			blocks = append(blocks, map[string]any{"type": "text", "text": msg.Text})
			messages = append(messages, map[string]any{"role": "user", "content": blocks})
			continue
		}

		messages = append(messages, map[string]any{"role": msg.Role, "content": msg.Text})
	}

	maxTokens := m.MaxTokens
	if maxTokens == 0 {
		maxTokens = DefaultAnthropicMaxTokens
	}
	if maxTokens < 1 {
		return out, errors.New("max tokens for the Anthropic provider must be positive")
	}

	payload := map[string]any{"model": m.ModelName, "max_tokens": maxTokens, "messages": messages}
	if system = strings.TrimSpace(system); system != "" {
		block := map[string]any{"type": "text", "text": system}
		if !m.DisablePromptCache {
			block["cache_control"] = map[string]any{"type": "ephemeral"}
		}

		payload["system"] = []any{block}
	}
	if m.Temperature != nil {
		payload["temperature"] = *m.Temperature
	}
	if len(specs) > 0 {
		tools := []any{}
		for _, s := range specs {
			tools = append(tools,
				map[string]any{"name": s.Name, "description": s.Description, "input_schema": s.Parameters})
		}

		payload["tools"] = tools
		if m.forceTool != "" {
			payload["tool_choice"] = map[string]any{"type": "tool", "name": m.forceTool}
		}
	}

	status, body, err := postJSON(ctx, m.Client, 90*time.Second, endpoint,
		map[string]string{"x-api-key": m.APIKey, "anthropic-version": "2023-06-01"}, payload)
	if err != nil {
		return out, err
	}
	if status < 200 || status > 299 {
		reason := apiError(body)
		// Some models reject the temperature field outright. Retry once
		// without it and remember, rather than failing every request.
		if m.Temperature != nil && refusedField(status, reason, "temperature") != "" {
			m.Refused.add("temperature")
			m.Temperature = nil
			return m.Generate(ctx, history, specs)
		}
		// Some models refuse a forced tool choice; offer the tool unforced
		// instead (GenerateStructured then takes the call or the text).
		if m.forceTool != "" && refusedField(status, reason, "tool_choice") != "" {
			m.Refused.add("tool_choice")
			m.forceTool = ""
			return m.Generate(ctx, history, specs)
		}
		return out, fmt.Errorf("anthropic: HTTP status %d: %s", status, reason)
	}

	var decoded struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			Input  int `json:"input_tokens"`
			Output int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return out, err
	}
	for _, block := range decoded.Content {
		switch block.Type {
		case "text":
			if out.Text != "" {
				out.Text += "\n"
			}

			out.Text += block.Text
		case "tool_use":
			if block.ID == "" || block.Name == "" || !json.Valid(block.Input) {
				return Response{}, errors.New("invalid Anthropic tool use")
			}

			out.Calls = append(out.Calls, Call{ID: block.ID, Name: block.Name, Arguments: block.Input})
		}
	}

	out.InputTokens = decoded.Usage.Input
	out.OutputTokens = decoded.Usage.Output
	if decoded.StopReason == "max_tokens" {
		return out, fmt.Errorf("anthropic %w (max_tokens %d)", ErrReplyLength, maxTokens)
	}
	if out.Text == "" && len(out.Calls) == 0 {
		return out, errors.New("anthropic: model returned no content")
	}

	return out, nil
}
