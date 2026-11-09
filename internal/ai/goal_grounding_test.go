// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"strings"
	"testing"
)

const alternateFixtureQuestion = "Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?"

func TestExplicitRelationGroundingRecoversHallucinatedRegistration(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"connected","relationships":[{"source_type":"FQDN","label":"registration","relation_type":"SimpleRelation","destination_type":"DomainRecord"}],"path_rule":"any"}`,
	}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: examplePlannedGraph(), Catalog: testOAMCatalog, Limits: DefaultLimits()}}
	goal, err := agent.planGoal(context.Background(), alternateFixtureQuestion)
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 1 {
		t.Fatalf("schema grounding should not require model retry; got %d calls", model.calls)
	}
	if goal.Subject.Type != "FQDN" || goal.Subject.Value != "tech.acme.example" || len(goal.TargetTypes) != 1 || goal.TargetTypes[0] != "Organization" {
		t.Fatalf("grounding changed user identifier or target: %+v", goal)
	}
	if goal.PathRule != "all" || len(goal.Relationships) != 2 {
		t.Fatalf("expected two exact named labels: %+v", goal)
	}
	if goal.Relationships[0].Label != "domain" || goal.Relationships[0].SourceType != "URL" ||
		goal.Relationships[0].DestinationType != "FQDN" ||
		goal.Relationships[1].Label != "website" || goal.Relationships[1].SourceType != "Organization" ||
		goal.Relationships[1].DestinationType != "URL" {
		t.Fatalf("recovery invented or reordered the OAM schema path: %+v", goal.Relationships)
	}
	if err := validateGoal(goal, testOAMCatalog.Relations(), testOAMCatalog.SearchFields()); err != nil {
		t.Fatal(err)
	}
	t.Logf("REPAIRED GOAL: %s -> %s using %s and %s, rule=%s", goal.Subject.Type, goal.TargetTypes[0], goal.Relationships[0].Label, goal.Relationships[1].Label, goal.PathRule)
}

func TestExplicitRelationGroundingPreservesOrderedUserIntent(t *testing.T) {
	question := "Starting from tech.acme.example, find organizations via domain then website relationships in that order"
	hint, ok := explicitRelationLabels(question, testOAMCatalog.Relations())
	if !ok || hint.Rule != "ordered" {
		t.Fatalf("ordered labels were not detected: %+v", hint)
	}
	rels, ok := groundedRelationshipGoal(hint, "FQDN", "Organization", testOAMCatalog.Relations())
	if !ok || len(rels) != 2 || rels[0].Label != "domain" || rels[1].Label != "website" {
		t.Fatalf("ordered schema route not grounded: %+v", rels)
	}
}

func TestExplicitRelationGroundingRejectsAmbiguousTaxonomy(t *testing.T) {
	catalog := planCatalog{
		{SourceType: "FQDN", Label: "domain", RelationType: "SimpleRelation", DestinationType: "URL"},
		{SourceType: "URL", Label: "website", RelationType: "SimpleRelation", DestinationType: "Organization"},
		{SourceType: "FQDN", Label: "domain", RelationType: "SimpleRelation", DestinationType: "Service"},
		{SourceType: "Service", Label: "website", RelationType: "SimpleRelation", DestinationType: "Organization"},
	}
	hint, ok := explicitRelationLabels(alternateFixtureQuestion, catalog)
	if !ok {
		t.Fatal("explicit labels not detected")
	}
	if _, ok := groundedRelationshipGoal(hint, "FQDN", "Organization", catalog); ok {
		t.Fatal("ambiguous schema paths must not be guessed")
	}
}

func TestExplicitRelationGroundingFailsClosedWhenTargetTypeHallucinated(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["ImaginaryOrganization"],"direction":"both","purpose":"connected","relationships":[],"path_rule":""}`,
	}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: examplePlannedGraph(), Catalog: testOAMCatalog, Limits: DefaultLimits()}}
	_, err := agent.planGoal(context.Background(), alternateFixtureQuestion)
	if err == nil || !strings.Contains(err.Error(), "unknown OAM target type") {
		t.Fatalf("invented target was accepted: %v", err)
	}
}

func TestNonExplicitQuestionDoesNotTriggerRelationRepair(t *testing.T) {
	hint, ok := explicitRelationLabels("What organization is associated with tech.acme.example?", testOAMCatalog.Relations())
	if ok || len(hint.Labels) != 0 {
		t.Fatalf("association question was incorrectly constrained: %+v", hint)
	}
}
