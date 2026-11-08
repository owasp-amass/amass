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
	"time"
)

// AnthropicModel is a native Messages API implementation of the common Model.
type AnthropicModel struct {
	Endpoint  string
	ModelName string
	APIKey    string
	Client    *http.Client
}

func (m AnthropicModel) Generate(ctx context.Context, history []Message, specs []ToolSpec) (Response, error) {
	var out Response
	if m.ModelName == "" || m.APIKey == "" {
		return out, errors.New("Anthropic model and API key required")
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
			messages = append(messages, map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": msg.ToolCallID, "content": msg.Text}}})
			continue
		}
		if msg.Role == "assistant" && len(msg.Calls) > 0 {
			blocks := []any{}
			if msg.Text != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": msg.Text})
			}
			for _, call := range msg.Calls {
				blocks = append(blocks, map[string]any{"type": "tool_use", "id": call.ID, "name": call.Name, "input": json.RawMessage(call.Arguments)})
			}
			messages = append(messages, map[string]any{"role": "assistant", "content": blocks})
			continue
		}
		if msg.Role != "user" && msg.Role != "assistant" {
			return out, fmt.Errorf("unknown message role %q", msg.Role)
		}
		messages = append(messages, map[string]any{"role": msg.Role, "content": msg.Text})
	}
	payload := map[string]any{"model": m.ModelName, "system": system, "max_tokens": 2048, "messages": messages}
	if len(specs) > 0 {
		tools := []any{}
		for _, s := range specs {
			tools = append(tools, map[string]any{"name": s.Name, "description": s.Description, "input_schema": s.Parameters})
		}
		payload["tools"] = tools
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", m.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
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
		return out, fmt.Errorf("Anthropic HTTP status %d", resp.StatusCode)
	}
	var decoded struct {
		Content []struct {
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
	if out.Text == "" && len(out.Calls) == 0 {
		return out, errors.New("Anthropic returned no content")
	}
	return out, nil
}
