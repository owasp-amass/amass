// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// generateJSON asks model for a JSON reply, constrained by schema when the
// provider supports it and otherwise relying on the prompt. Tool calls are
// rejected either way.
func generateJSON(ctx context.Context, model llm.Model, history []llm.Message, schema llm.JSONSchema) (llm.Response, error) {
	var (
		resp llm.Response
		err  error
	)
	if sm, ok := model.(llm.StructuredModel); ok && len(schema.Schema) > 0 {
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

var _ llm.StructuredModel = llm.AnthropicModel{}
