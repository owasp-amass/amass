// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"reflect"
	"testing"
)

// schemaModel records the schema it was asked to honor and returns reply.
type schemaModel struct {
	reply  string
	schema JSONSchema
}

func (m *schemaModel) Generate(context.Context, []Message, []ToolSpec) (Response, error) {
	return Response{Text: m.reply}, nil
}

func (m *schemaModel) GenerateStructured(_ context.Context, _ []Message, s JSONSchema) (Response, error) {
	m.schema = s
	return Response{Text: m.reply}, nil
}

func enumOf(t *testing.T, schema JSONSchema, property string) []string {
	t.Helper()

	props, _ := schema.Schema["properties"].(map[string]any)
	prop, ok := props[property].(map[string]any)
	if !ok {
		t.Fatalf("schema %s has no property %s", schema.Name, property)
	}
	if items, ok := prop["items"].(map[string]any); ok {
		prop = items
	}

	values, _ := prop["enum"].([]string)
	return values
}

func TestPathSelectionSchemaListsOnlyCandidates(t *testing.T) {
	s := pathSelectionSchema([]adaptiveCandidate{{PathID: "p2"}, {PathID: "p1"}, {PathID: "p2"}})
	if got := enumOf(t, s, "selected_path_ids"); !reflect.DeepEqual(got, []string{"p1", "p2"}) {
		t.Fatalf("path enum = %v, want [p1 p2]", got)
	}
}

func TestEmptyEnumArrayForbidsItems(t *testing.T) {
	got := enumArray(nil, 5)
	if got["maxItems"] != 0 || got["items"] != nil {
		t.Fatalf("empty enum array = %v, want maxItems 0 and no items", got)
	}
}

func TestGuidanceSchemaUsesFrontierIDs(t *testing.T) {
	s := guidanceSchema(guidedSummary{
		AllowedLabels: []string{"node", "dns_record"},
		Pending:       []GuidedFrontier{{AssetID: "a1", PathID: "p1"}, {AssetID: "a2", PathID: "p2"}},
	})
	if got := enumOf(t, s, "preferred_labels"); !reflect.DeepEqual(got, []string{"dns_record", "node"}) {
		t.Fatalf("label enum = %v", got)
	}
	if got := enumOf(t, s, "priority_asset_ids"); !reflect.DeepEqual(got, []string{"a1", "a2"}) {
		t.Fatalf("asset enum = %v", got)
	}
	if got := enumOf(t, s, "priority_path_ids"); !reflect.DeepEqual(got, []string{"p1", "p2"}) {
		t.Fatalf("path enum = %v", got)
	}
}

func TestInferrerSendsProposalSchema(t *testing.T) {
	c := Candidate{
		SubjectID: "o1", ObjectID: "o2", AllowedLabels: []string{"subsidiary"},
		Evidence: []Evidence{{ID: "e1", SourceID: "s1"}, {ID: "e2", SourceID: "s2"}},
	}
	m := &schemaModel{reply: `{"subject_id":"o1","predicate":"subsidiary","object_id":"o2","confidence":0.8,` +
		`"reason":"shared registrant and filings","evidence_ids":["e1","e2"],"contradictions":[]}`}

	p, err := Inferrer{Model: m, MinSources: 2}.Analyze(context.Background(), c)
	if err != nil || p == nil {
		t.Fatalf("Analyze() = %v, %v; want a proposal", p, err)
	}
	if m.schema.Name != "relation_proposal" {
		t.Fatalf("schema name = %q, want relation_proposal", m.schema.Name)
	}
	if got := enumOf(t, m.schema, "predicate"); !reflect.DeepEqual(got, []string{"none", "subsidiary"}) {
		t.Fatalf("predicate enum = %v", got)
	}
	if got := enumOf(t, m.schema, "evidence_ids"); !reflect.DeepEqual(got, []string{"e1", "e2"}) {
		t.Fatalf("evidence enum = %v", got)
	}
}
