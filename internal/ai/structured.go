// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// ErrUnreadableReply is a reply that is not the JSON asked for, even after
// one reminder.
var ErrUnreadableReply = errors.New("unreadable model reply")

// maxEchoedReply bounds the unreadable reply quoted back to the model with
// the reminder.
const maxEchoedReply = 2000

// decodeJSON asks model for a JSON reply (generateJSON) and decodes it into
// v. A reply that is not JSON, such as a prose answer, is asked again once
// with the reply and a reminder to answer with only the JSON object. A
// failed request is returned as it is; a reply still unreadable wraps
// ErrUnreadableReply.
func decodeJSON(ctx context.Context, model llm.Model, history []llm.Message, schema llm.JSONSchema, v any) error {
	resp, err := generateJSON(ctx, model, history, schema)
	if err != nil {
		return err
	}
	if json.Unmarshal([]byte(llm.ModelJSON(resp.Text)), v) == nil {
		return nil
	}

	echo := resp.Text
	if len(echo) > maxEchoedReply {
		echo = echo[:maxEchoedReply]
	}
	if echo == "" {
		echo = "(no reply)"
	}
	retry := append(append([]llm.Message{}, history...), llm.Message{Role: "assistant", Text: echo},
		llm.Message{Role: "user", Text: "That reply was not the JSON object asked for. Answer again with only " +
			"the JSON object, with every required field, and no other text."})
	resp, err = generateJSON(ctx, model, retry, schema)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(llm.ModelJSON(resp.Text)), v); err != nil {
		return fmt.Errorf("%w: %w", ErrUnreadableReply, err)
	}
	return nil
}

// requestErr is err, unless only the reply was unreadable: the request
// itself succeeded, so a breaker does not count it.
func requestErr(err error) error {
	if errors.Is(err, ErrUnreadableReply) {
		return nil
	}
	return err
}

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
