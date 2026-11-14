// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestGoalRelationshipsAnyAllOrderedAndDirections(t *testing.T) {
	g := examplePlannedGraph()
	root := g.Assets["fqdn-tech"]
	url := g.Assets["website-tech"]
	tech := g.Assets["tech"]
	parent := g.Assets["parent"]
	path := graph.PlanMatch{Nodes: []graph.Asset{root, url, tech, parent}, Edges: []graph.Relation{
		{ID: "e5", FromID: "website-tech", ToID: "fqdn-tech", Label: "domain", Type: "SimpleRelation"},
		{ID: "e3", FromID: "tech", ToID: "website-tech", Label: "website", Type: "SimpleRelation"},
		{ID: "e1", FromID: "parent", ToID: "tech", Label: "subsidiary", Type: "SimpleRelation"},
	}}
	domain := GoalRelation{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"}
	website := GoalRelation{
		SourceType:      "Organization",
		Label:           "website",
		RelationType:    "SimpleRelation",
		DestinationType: "URL",
	}
	subsidiary := GoalRelation{
		SourceType:      "Organization",
		Label:           "subsidiary",
		RelationType:    "SimpleRelation",
		DestinationType: "Organization",
	}
	if !pathSatisfiesGoal(path, []GoalRelation{website}, "any") {
		t.Fatal("website relationship not found")
	}
	if !pathSatisfiesGoal(path, []GoalRelation{website, domain}, "all") {
		t.Fatal("unordered all did not match")
	}
	if !pathSatisfiesGoal(path, []GoalRelation{domain, website, subsidiary}, "ordered") {
		t.Fatal("reverse traversed path must match stored-edge orientations in encounter order")
	}
	if pathSatisfiesGoal(path, []GoalRelation{subsidiary, website, domain}, "ordered") {
		t.Fatal("ordered constraints incorrectly reversed")
	}
	if pathSatisfiesGoal(path,
		[]GoalRelation{
			{SourceType: "FQDN", Label: "domain", RelationType: "SimpleRelation", DestinationType: "URL"},
		}, "any") {
		t.Fatal("inverse traversal was incorrectly treated as inverse stored assertion")
	}
	if err := validGoalRelations([]GoalRelation{domain, website}, "ordered", graphtest.TestOAMCatalog.Relations()); err != nil {
		t.Fatal(err)
	}
	if err := validGoalRelations([]GoalRelation{
		{SourceType: "URL", Label: "unknown", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	}, "any", graphtest.TestOAMCatalog.Relations()); err == nil {
		t.Fatal("unregistered relation accepted")
	}
	if err := validGoalRelations([]GoalRelation{domain}, "everything", graphtest.TestOAMCatalog.Relations()); err == nil {
		t.Fatal("unsupported quantifier accepted")
	}

	t.Logf("validated any/all/ordered path constraints across FQDN -> URL -> Organization -> Organization")
}

func TestGuidedGraphRespectsExactRelationshipGoal(t *testing.T) {
	g := examplePlannedGraph()
	req := GuidedSearchRequest{GraphSearchRequest: GraphSearchRequest{
		StartID:     "fqdn-tech",
		TargetTypes: []string{"Organization"},
		MaxDepth:    8,
	},
		Relationships: []GoalRelation{
			{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
			{SourceType: "Organization", Label: "website", RelationType: "SimpleRelation", DestinationType: "URL"},
			{
				SourceType:      "Organization",
				Label:           "subsidiary",
				RelationType:    "SimpleRelation",
				DestinationType: "Organization",
			},
		},
		PathRule: "ordered", MaxPathsPerAsset: 3,
	}
	e, err := NewGuidedExplorer(context.Background(), g, graphtest.TestOAMCatalog, graph.DefaultLimits(), req)
	if err != nil {
		t.Fatal(err)
	}

	_, err = e.Advance(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}

	found := e.Result().Matches
	if len(found) != 2 {
		t.Fatalf("expected parent and sibling along ordered three-edge traversal, got %+v", found)
	}
	for _, p := range found {
		if len(p.Edges) < 3 {
			t.Fatalf("ordered requirement matched too-short path: %+v", p)
		}
	}

	t.Logf("ordered relationship goal matched %d schema-grounded paths", len(found))
}

func TestUnspecifiedGoalMaintainsLegacySemantics(t *testing.T) {
	goal := InvestigationGoal{Subject: PlanSubject{Type: "FQDN", Field: "name", Value: "tech.acme.example"},
		TargetTypes: []string{"Organization"}, Direction: "both", Purpose: "connected"}
	if err := validateGoal(goal, graphtest.TestOAMCatalog.Relations(), graphtest.TestOAMCatalog.SearchFields()); err != nil {
		t.Fatal(err)
	}
	if !pathSatisfiesGoal(graph.PlanMatch{}, nil, "") {
		t.Fatal("unspecified relation constraints must not suppress exploratory questions")
	}
}
