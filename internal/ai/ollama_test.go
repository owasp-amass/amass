// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

func TestGoalSchemaEnumeratesCatalogAndMetersUsage(t *testing.T) {
	schema := goalJSONSchema(aitest.TestOAMCatalog.Relations(), aitest.TestOAMCatalog.SearchFields())
	props := schema.Schema["properties"].(map[string]any)
	allowed := props["relationships"].(map[string]any)["items"].(map[string]any)["enum"].([]any)
	if len(allowed) != len(aitest.TestOAMCatalog) {
		t.Fatalf("each catalog transition must be one allowed value: %v", allowed)
	}
	for i, want := range aitest.TestOAMCatalog {
		got := allowed[i].(map[string]any)
		if got["source_type"] != want.SourceType || got["label"] != want.Label ||
			got["relation_type"] != want.RelationType || got["destination_type"] != want.DestinationType {
			t.Fatalf("transition %d: got %v want %+v", i, got, want)
		}
	}

	// The planner uses structured generation; metering wraps it and counts usage.
	model := &structuredRecorder{
		reply: `{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["URL"],"direction":"both","purpose":"connected","relationships":[],"path_rule":""}`,
	}
	agent := Agent{Model: model, Runner: ToolRunner{Limits: graph.DefaultLimits(), Catalog: aitest.TestOAMCatalog}}
	agent, meter := agent.metered()
	q, err := agent.CompileQuestion(context.Background(), "Tell me about the URLs near tech.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if q.Source != SourceModelGoal || model.structured != 1 || model.plain != 0 {
		t.Fatalf("planner must use structured generation: %+v %+v", q, model)
	}
	if u := meter.Snapshot(); u.Calls != 1 || u.InputTokens != 100 || u.OutputTokens != 20 {
		t.Fatalf("usage not metered: %+v", u)
	}
}

type structuredRecorder struct {
	reply             string
	structured, plain int
}

func (m *structuredRecorder) Generate(context.Context, []llm.Message, []llm.ToolSpec) (llm.Response, error) {
	m.plain++
	return llm.Response{Text: m.reply}, nil
}

func (m *structuredRecorder) GenerateStructured(_ context.Context, _ []llm.Message, s llm.JSONSchema) (llm.Response, error) {
	m.structured++
	if s.Name != "investigation_goal" {
		return llm.Response{}, nil
	}

	return llm.Response{Text: m.reply, InputTokens: 100, OutputTokens: 20}, nil
}
