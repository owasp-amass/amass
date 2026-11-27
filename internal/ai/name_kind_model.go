// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"slices"
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// NameKindModel lets the main model answer what a name found in a person's
// field names, when the words and the graph left it uncertain. It only
// answers: the engine applies the answer or keeps it as advice, by the
// attribution mode and the answer's confidence.
type NameKindModel struct {
	Model   llm.Model
	ModelID string
	// Breaker, shared with the session's other deciders, stops asking a
	// model that keeps failing; nil never stops.
	Breaker *ModelBreaker
}

var _ et.NameKindDecider = (*NameKindModel)(nil)

// Name implements et.NameKindDecider.
func (n *NameKindModel) Name() string {
	return "model " + n.ModelID
}

const nameKindInstructions = `You decide whether a name that a record gives in a field meant for a person names a person or an organization.
Registries and documents often put an organization's name where a person's belongs (a company as a domain's registrant contact, a university as a document's author), and some people's names look like organizations' (Morgan Stanley, Sarah Church).
Use only the evidence given, numbered from 1. Answer "unclear" when it does not settle the question; a wrong answer is worse than none.
Reply with JSON: kind "person", "organization" or "unclear", confidence from 0 to 1 that your kind is right, a one-sentence reason, and cites: the numbers of the evidence the reason rests on.`

var nameKindSchema = llm.JSONSchema{Name: "name_kind",
	Description: "Whether the name names a person or an organization",
	Schema: map[string]any{"type": "object", "additionalProperties": false,
		"required": []string{"kind", "confidence", "reason", "cites"},
		"properties": map[string]any{
			"kind": map[string]any{"type": "string",
				"enum": []string{et.NameKindPerson, et.NameKindOrganization, et.NameKindUnclear}},
			"confidence": map[string]any{"type": "number", "minimum": 0, "maximum": 1},
			"reason":     map[string]any{"type": "string"},
			"cites":      map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
		}}}

// Decide implements et.NameKindDecider. An answer that names a kind must
// cite the evidence it rests on, or it is refused.
func (n *NameKindModel) Decide(ctx context.Context, q *et.NameKindQuestion) (et.NameKindAnswer, error) {
	if n == nil || n.Model == nil || q == nil || strings.TrimSpace(q.Name) == "" {
		return et.NameKindAnswer{}, fmt.Errorf("no model or no name to decide")
	}

	if !n.Breaker.Allow() {
		return et.NameKindAnswer{}, ErrModelStopped
	}

	history := []llm.Message{{Role: "system", Text: nameKindInstructions}, {Role: "user", Text: nameKindCase(q)}}
	var reply struct {
		Kind       string  `json:"kind"`
		Confidence float64 `json:"confidence"`
		Reason     string  `json:"reason"`
		Cites      []int   `json:"cites"`
	}
	err := decodeJSON(ctx, n.Model, history, nameKindSchema, &reply)
	n.Breaker.Record(requestErr(err))
	if err != nil {
		return et.NameKindAnswer{}, err
	}

	a := et.NameKindAnswer{Kind: strings.ToLower(strings.TrimSpace(reply.Kind)),
		Confidence: int(min(max(reply.Confidence, 0), 1) * 100), Reason: strings.TrimSpace(reply.Reason)}
	if len(a.Reason) > 400 {
		a.Reason = a.Reason[:400]
	}
	switch a.Kind {
	case et.NameKindPerson, et.NameKindOrganization:
	case et.NameKindUnclear:
		return a, nil
	default:
		return et.NameKindAnswer{}, fmt.Errorf("the model answered kind %q", reply.Kind)
	}

	for _, c := range reply.Cites {
		if c < 1 || c > len(q.Evidence) {
			return et.NameKindAnswer{}, fmt.Errorf("the model cited evidence %d of %d", c, len(q.Evidence))
		}
		if !slices.Contains(a.Cites, c) {
			a.Cites = append(a.Cites, c)
		}
	}
	if len(a.Cites) == 0 {
		return et.NameKindAnswer{}, fmt.Errorf("the model answered %s without citing evidence", a.Kind)
	}
	return a, nil
}

// nameKindCase describes the question for the model.
func nameKindCase(q *et.NameKindQuestion) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Name: %q\nGiven by: a %s, in its %s field", q.Name, q.RecordType, q.Label)
	if q.Source != "" {
		fmt.Fprintf(&b, ", read by %s", q.Source)
	}
	b.WriteString("\nEvidence:\n")
	if len(q.Evidence) == 0 {
		b.WriteString("(none)\n")
	}
	for i, ev := range q.Evidence {
		fmt.Fprintf(&b, "%d. %s\n", i+1, ev)
	}
	return b.String()
}
