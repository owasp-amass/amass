// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"testing"
)

func TestAnswerGroupingCollapsesEquivalentRoutesWithoutModelCall(t *testing.T) {
	graph := diamondGuidedGraph()
	graph.evidence = map[string][]Evidence{
		"d1": {{ID: "d1-s", SubjectID: "d1", Kind: "SourceProperty", SourceID: "source-a"}},
		"d2": {{ID: "d2-s1", SubjectID: "d2", Kind: "SourceProperty", SourceID: "source-a"},
			{ID: "d2-s2", SubjectID: "d2", Kind: "SourceProperty", SourceID: "source-b"}},
		"w2": {{ID: "w2-s1", SubjectID: "w2", Kind: "SourceProperty", SourceID: "source-a"},
			{ID: "w2-s2", SubjectID: "w2", Kind: "SourceProperty", SourceID: "source-b"}},
	}
	exp, err := NewGuidedExplorer(context.Background(), graph, testOAMCatalog, DefaultLimits(), GuidedSearchRequest{
		GraphSearchRequest: GraphSearchRequest{StartID: "f", TargetTypes: []string{"Organization"}, MaxDepth: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = exp.Advance(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := exp.Result().Matches
	if len(paths) != 2 {
		t.Fatalf("expected 2 alternatives, got %d", len(paths))
	}
	dossier, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), paths)
	if err != nil {
		t.Fatal(err)
	}
	model := &plannerModel{replies: []string{`{"selected_path_ids":[]}`}}
	selected, groups, deterministic, err := (Agent{Model: model}).selectAnswerPaths(context.Background(), "Which organization?", InvestigationGoal{Purpose: "connected"}, paths, &dossier)
	if err != nil {
		t.Fatal(err)
	}
	if !deterministic || model.calls != 0 || len(groups) != 1 || len(selected) != 1 {
		t.Fatalf("equivalent routes should not require a model: groups=%+v selected=%+v calls=%d", groups, selected, model.calls)
	}
	if len(groups[0].AlternativePathIDs) != 1 || groups[0].PreferredPathID != selected[0].PathID {
		t.Fatalf("lost alternative path or selected wrong representative: %+v", groups[0])
	}
	ev := map[string]PathEvidence{}
	for _, p := range dossier.Paths {
		ev[p.PathID] = p
	}
	if ev[selected[0].PathID].Status != "multiple_source_tags_on_each_edge" {
		t.Fatalf("preferred route not the better tagged witness: %+v", selected[0])
	}
}

func TestAnswerGroupingKeepsIndirectOrganizationsAsContext(t *testing.T) {
	graph := examplePlannedGraph()
	goal := InvestigationGoal{Purpose: "connected", TargetTypes: []string{"Organization"}, Direction: "both",
		Relationships: []GoalRelation{
			{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
			{SourceType: "Organization", Label: "website", RelationType: "SimpleRelation", DestinationType: "URL"},
		}, PathRule: "all"}
	exp, err := NewGuidedExplorer(context.Background(), graph, testOAMCatalog, DefaultLimits(), GuidedSearchRequest{
		GraphSearchRequest: GraphSearchRequest{StartID: "fqdn-tech", TargetTypes: goal.TargetTypes, MaxDepth: 8},
		Relationships:      goal.Relationships, PathRule: goal.PathRule,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = exp.Advance(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := eligibleAdaptivePaths(goal, exp.Result().Matches)
	dossier, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), paths)
	if err != nil {
		t.Fatal(err)
	}
	model := &plannerModel{replies: []string{`{"selected_path_ids":[]}`}}
	selected, groups, deterministic, err := (Agent{Model: model}).selectAnswerPaths(context.Background(), "Organization via domain and website?", goal, paths, &dossier)
	if err != nil {
		t.Fatal(err)
	}
	if !deterministic || model.calls != 0 || len(selected) != 1 || selected[0].Nodes[len(selected[0].Nodes)-1].ID != "tech" {
		t.Fatalf("indirect parent/sibling was not separated from direct answer: %+v", selected)
	}
	contextual := 0
	for _, g := range groups {
		if !g.DirectToGoal {
			contextual++
		}
	}
	if contextual != 2 {
		t.Fatalf("expected parent and sibling to remain contextual: %+v", groups)
	}
}

func TestAnswerGroupingDoesNotCollapseDifferentRelationshipMeanings(t *testing.T) {
	root := Asset{ID: "f", Type: "FQDN", Key: "demo.example"}
	url := Asset{ID: "u", Type: "URL", Key: "https://demo.example"}
	org := Asset{ID: "o", Type: "Organization", Key: "synthetic-org"}
	first := PlanMatch{Nodes: []Asset{root, url, org}, Edges: []Relation{
		{ID: "domain-edge", FromID: "u", ToID: "f", Label: "domain", Type: "SimpleRelation"},
		{ID: "website-edge", FromID: "o", ToID: "u", Label: "website", Type: "SimpleRelation"},
	}}
	second := PlanMatch{Nodes: []Asset{root, org}, Edges: []Relation{
		{ID: "verified-edge", FromID: "f", ToID: "o", Label: "verified_for", Type: "SimpleRelation"},
	}}
	first.PathID = WitnessPathID(first)
	second.PathID = WitnessPathID(second)
	model := &plannerModel{replies: []string{
		`{"selected_path_ids":["` + first.PathID + `"]}`,
	}}
	selected, groups, deterministic, err := (Agent{Model: model}).selectAnswerPaths(context.Background(),
		"Which organization has a documented website versus verified-for relationship?",
		InvestigationGoal{Purpose: "connected"}, []PlanMatch{first, second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if deterministic || model.calls != 1 || len(groups) != 2 || len(selected) != 1 {
		t.Fatalf("heterogeneous relationships must remain model-selectable: groups=%+v selected=%+v calls=%d", groups, selected, model.calls)
	}
	if groups[0].SemanticSignature == groups[1].SemanticSignature {
		t.Fatalf("different relationship meanings were collapsed: %+v", groups)
	}
	if selected[0].PathID != first.PathID {
		t.Fatalf("model selected wrong witnessed route: %+v", selected)
	}
}
