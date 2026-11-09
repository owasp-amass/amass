// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
)

// JSONSchema names a JSON Schema object that a structured reply must match.
type JSONSchema struct {
	Name        string
	Description string
	Schema      map[string]any
}

// StructuredModel is implemented by providers that can constrain a reply to
// a JSON schema at generation time. The reply JSON is returned in Text.
// Callers must still decode and validate it: a schema narrows what a model
// can say, but only Go validation against the OAM catalog makes it valid.
type StructuredModel interface {
	GenerateStructured(ctx context.Context, history []Message, schema JSONSchema) (Response, error)
}

// generateJSON asks model for a JSON reply, constrained by schema when the
// provider supports it and otherwise relying on the prompt. Tool calls are
// rejected either way.
func generateJSON(ctx context.Context, model Model, history []Message, schema JSONSchema) (Response, error) {
	var (
		resp Response
		err  error
	)
	if sm, ok := model.(StructuredModel); ok && len(schema.Schema) > 0 {
		resp, err = sm.GenerateStructured(ctx, history, schema)
	} else {
		resp, err = model.Generate(ctx, history, nil)
	}
	if err != nil {
		return resp, err
	}
	if len(resp.Calls) != 0 {
		return resp, errors.New("model requested a tool call instead of returning JSON")
	}

	return resp, nil
}

// GenerateStructured implements StructuredModel by offering exactly one tool
// whose input schema is the requested schema and forcing the model to call
// it. The tool input is returned as the reply text.
func (m AnthropicModel) GenerateStructured(ctx context.Context, history []Message, schema JSONSchema) (Response, error) {
	if schema.Name == "" || len(schema.Schema) == 0 {
		return Response{}, errors.New("structured generation requires a named JSON schema")
	}

	spec := ToolSpec{Name: schema.Name, Description: schema.Description, Parameters: schema.Schema}
	if spec.Description == "" {
		spec.Description = "Return the result as the input of this tool."
	}

	forced := m
	forced.forceTool = schema.Name
	resp, err := forced.Generate(ctx, history, []ToolSpec{spec})
	if err != nil {
		return resp, err
	}
	for _, c := range resp.Calls {
		if c.Name == schema.Name {
			return Response{
				Text:         string(c.Arguments),
				InputTokens:  resp.InputTokens,
				OutputTokens: resp.OutputTokens,
			}, nil
		}
	}

	return Response{}, errors.New("anthropic: model did not return the structured result")
}

var _ StructuredModel = AnthropicModel{}
