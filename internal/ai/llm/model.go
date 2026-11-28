// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
)

type Message struct {
	Role       string `json:"role"`
	Text       string `json:"text,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Calls      []Call `json:"calls,omitempty"`
	// Images are pictures a user message shows a model that can see them,
	// such as the pages of a scanned document.
	Images []Image `json:"images,omitempty"`
}

// Image is a picture in a message: its media type (image/jpeg, image/png)
// and its bytes.
type Image struct {
	MediaType string `json:"media_type"`
	Data      []byte `json:"data"`
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
