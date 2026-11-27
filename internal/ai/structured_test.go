// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// historyModel replies with each text in turn and keeps what it was sent.
type historyModel struct {
	replies []string
	sent    [][]llm.Message
}

func (m *historyModel) Generate(_ context.Context, h []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	m.sent = append(m.sent, h)
	return llm.Response{Text: m.replies[min(len(m.sent)-1, len(m.replies)-1)]}, nil
}

// A prose reply is asked again once, with the reply and a reminder; a
// second prose reply is unreadable.
func TestDecodeJSONAsksAgainOnce(t *testing.T) {
	history := []llm.Message{{Role: "system", Text: "Reply with JSON."}, {Role: "user", Text: "Is mcarr a person?"}}
	var reply struct {
		Kind string `json:"kind"`
	}

	m := &historyModel{replies: []string{"mcarr is most likely a person's login.", `{"kind":"person"}`}}
	if err := decodeJSON(context.Background(), m, history, nameKindSchema, &reply); err != nil || reply.Kind != "person" {
		t.Fatalf("after the reminder: %+v, %v", reply, err)
	}
	if len(m.sent) != 2 || len(m.sent[1]) != 4 || m.sent[1][2].Role != "assistant" ||
		!strings.Contains(m.sent[1][2].Text, "mcarr") || !strings.Contains(m.sent[1][3].Text, "only the JSON") {
		t.Fatalf("retry history = %+v", m.sent)
	}
	if len(history) != 2 {
		t.Error("the caller's history was changed")
	}

	m = &historyModel{replies: []string{"a person", "still a person"}}
	err := decodeJSON(context.Background(), m, history, nameKindSchema, &reply)
	if !errors.Is(err, ErrUnreadableReply) || len(m.sent) != 2 {
		t.Fatalf("two prose replies: %v after %d requests", err, len(m.sent))
	}
	if requestErr(err) != nil {
		t.Error("an unreadable reply counted as a failed request")
	}

	m = &historyModel{replies: []string{`{"kind":"organization"}`}}
	if err := decodeJSON(context.Background(), m, history, nameKindSchema, &reply); err != nil || len(m.sent) != 1 {
		t.Fatalf("a JSON reply: %v after %d requests", err, len(m.sent))
	}
}
