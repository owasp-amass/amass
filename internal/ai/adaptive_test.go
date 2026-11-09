// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAdaptiveAskFindsParentWithoutSibling(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"ultimate_parent"}`,
	}}
	runner := ToolRunner{Graph: examplePlannedGraph(), Catalog: testOAMCatalog, Limits: DefaultLimits()}
	out, err := (Agent{Model: model, Runner: runner}).Ask(context.Background(),
		"What is the highest parent organization associated with tech.acme.example?")
	if err != nil {
		t.Fatal(err)
	}
	if out.Goal == nil || out.Search == nil || out.Incomplete || len(out.Matches) != 1 {
		t.Fatalf("unexpected adaptive result: %+v", out)
	}

	last := out.Matches[0].Nodes[len(out.Matches[0].Nodes)-1]
	if last.ID != "parent" || len(out.Matches[0].Edges) != 3 {
		t.Fatalf("parent should be depth 3 without sibling: %+v", out.Matches)
	}
	if model.calls != 1 || out.ToolCalls != 2 {
		t.Fatalf("unexpected model/tool count: model=%d tools=%d", model.calls, out.ToolCalls)
	}
	if !strings.Contains(out.Answer, "Acme Holdings Inc.") || !strings.Contains(out.Diagram, "flowchart LR") {
		t.Fatalf("no human explanation or diagram: %+v", out)
	}
}

func TestAdaptiveAskSelectsOnlyWitnessedPaths(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"connected"}`,
		`{"selected_asset_ids":["parent","tech"]}`,
	}}
	runner := ToolRunner{Graph: examplePlannedGraph(), Catalog: testOAMCatalog, Limits: DefaultLimits()}
	out, err := (Agent{Model: model, Runner: runner}).Ask(context.Background(),
		"Which organizations are connected to tech.acme.example?")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Matches) != 2 || len(out.Matches[0].Edges) != 3 || len(out.Matches[1].Edges) != 2 || out.Incomplete {
		t.Fatalf("unexpected selected paths: %+v", out)
	}
	if model.calls != 2 || out.Goal == nil || out.Goal.Purpose != "connected" {
		t.Fatalf("model was not involved in intent and selection: %+v", out)
	}
}

func TestAdaptiveSelectionRejectsInventedAssetIDs(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"selected_asset_ids":["invented-database-id"]}`,
		`{"selected_asset_ids":["also-invented"]}`,
	}}
	paths := []PlanMatch{
		{Nodes: []Asset{{ID: "a", Type: "FQDN"}, {ID: "one", Type: "Organization"}}, Edges: []Relation{{ID: "edge1"}}},
		{Nodes: []Asset{{ID: "a", Type: "FQDN"}, {ID: "two", Type: "Organization"}}, Edges: []Relation{{ID: "edge2"}}},
	}
	_, err := (Agent{Model: model}).chooseAdaptivePaths(context.Background(), "Which organizations?",
		InvestigationGoal{Purpose: "connected"}, paths)
	if err == nil || !strings.Contains(err.Error(), "not witnessed") {
		t.Fatalf("invented asset IDs accepted: %v", err)
	}
}

func TestAdaptivePlanRejectsUnknownTargetAndHops(t *testing.T) {
	_, err := parseGoal(`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"connected","hops":[]}`, testOAMCatalog.SearchFields())
	if err == nil {
		t.Fatal("adaptive planner accepted unsupported fixed hop key")
	}

	goal, err := parseGoal(`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["NotAnOAMType"],"direction":"both","purpose":"connected"}`, testOAMCatalog.SearchFields())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGoal(goal, testOAMCatalog.Relations(), testOAMCatalog.SearchFields()); err == nil {
		t.Fatal("unknown OAM target type accepted")
	}
}

func TestAdaptiveSearchReturnedJSONRemainsMachineReadable(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"ultimate_parent"}`,
	}}
	runner := ToolRunner{Graph: examplePlannedGraph(), Catalog: testOAMCatalog, Limits: DefaultLimits()}
	out, err := (Agent{Model: model, Runner: runner}).Ask(context.Background(),
		"Highest parent organization of tech.acme.example?")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}

	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if data["goal"] == nil || data["search"] == nil || data["matches"] == nil || data["diagram"] == nil {
		t.Fatalf("adaptive investigation response missing fields: %s", raw)
	}
}
