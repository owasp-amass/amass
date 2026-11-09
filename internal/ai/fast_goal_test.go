// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"testing"
)

// The real Qwen3 acceptance question previously needed ~98s of goal
// planning plus ~219s of route selection. Both inference calls are
// avoidable for this precise, explicitly constrained OAM query shape.
func TestExplicitOrganizationQuestionUsesZeroModelCalls(t *testing.T) {
	model := &plannerModel{replies: []string{}}
	agent := Agent{Model: model, Runner: ToolRunner{
		Graph: examplePlannedGraph(), Catalog: testOAMCatalog, Limits: DefaultLimits(),
	}}
	question := "Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?"
	result, err := agent.AskAdaptive(context.Background(), question, AdaptiveOptions{MaxDepth: 8, GuidanceRounds: 0})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 0 {
		t.Fatalf("explicit goal and clear direct result should not invoke LLM, got %d model calls", model.calls)
	}
	if result.Goal == nil || result.Goal.PathRule != "all" || len(result.Goal.Relationships) != 2 {
		t.Fatalf("wrong grounded OAM goal: %+v", result.Goal)
	}
	if result.Search == nil || result.Search.Truncated || len(result.Search.Matches) != 3 {
		t.Fatalf("graph candidates incomplete: %+v", result.Search)
	}
	if len(result.Matches) != 1 || result.Matches[0].Nodes[len(result.Matches[0].Nodes)-1].ID != "tech" {
		t.Fatalf("direct Organization should be only primary result: %+v", result.Matches)
	}
	if len(result.AnswerGroups) != 3 || result.EvidenceDossier == nil || len(result.EvidenceDossier.Paths) != 3 {
		t.Fatalf("indirect candidates or evidence discarded: groups=%+v dossier=%+v", result.AnswerGroups,
			result.EvidenceDossier)
	}

	stages := map[string]string{}
	for _, event := range result.Trace {
		stages[event.Stage] = event.Detail
	}
	if stages["goal_planning"] != "deterministic_schema_grounding" ||
		stages["path_selection"] != "deterministic_destination_grouping" {
		t.Fatalf("missing model-bypass stage tracing: %+v", result.Trace)
	}

	t.Logf("FAST PATH: model_calls=%d, graph_candidates=%d, answer_groups=%d, selected=%d, planning=%s, selection=%s",
		model.calls, len(result.Search.Matches), len(result.AnswerGroups), len(result.Matches),
		stages["goal_planning"], stages["path_selection"])
}

func TestDeterministicGoalFastPathFailsClosedForAmbiguity(t *testing.T) {
	cases := []string{
		"Which organization is connected to https://tech.acme.example/ via domain and website relationships?",
		"Which organization is connected to tech.acme.example and other.example via domain and website relationships?",
		"Which organization is connected to user@tech.acme.example via domain and website relationships?",
		"What is the highest parent organization connected to tech.acme.example via domain and website relationships?",
		"Which organization is connected to tech.acme.example?",
	}
	for _, question := range cases {
		_, ok := deterministicExplicitOrganizationGoal(question, testOAMCatalog)
		if ok {
			t.Errorf("ambiguous question incorrectly bypassed model: %s", question)
		}
	}
}

func TestDeterministicGoalAcceptsRealWorldTwoLabelFQDN(t *testing.T) {
	question := "Which organization is connected to owasp.org through domain and website relationships?"
	goal, ok := deterministicExplicitOrganizationGoal(question, testOAMCatalog)
	if !ok || goal.Subject.Type != "FQDN" || goal.Subject.Value != "owasp.org" ||
		goal.Purpose != "connected" || len(goal.Relationships) != 2 {
		t.Fatalf("explicit two-label domain was not grounded: goal=%+v ok=%t", goal, ok)
	}
}

func BenchmarkDeterministicExplicitOrganizationGoal(b *testing.B) {
	question := "Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?"
	for i := 0; i < b.N; i++ {
		if _, ok := deterministicExplicitOrganizationGoal(question, testOAMCatalog); !ok {
			b.Fatal("explicit question unexpectedly fell back to the model")
		}
	}
}

// This graph reproduces the six candidates in the disposable semantic
// fixture: two equivalent direct routes, two routes to the parent, and two
// routes to the sibling. The better-tagged URL path must win without Qwen.
func TestSixPathAlternativeQuestionSelectsOneDirectRouteWithoutModel(t *testing.T) {
	g := fakeGraph{
		assets: map[string]Asset{
			"f":       {ID: "f", Type: "FQDN", Key: "tech.acme.example"},
			"u1":      {ID: "u1", Type: "URL", Key: "https://tech.acme.example/"},
			"u2":      {ID: "u2", Type: "URL", Key: "https://tech.acme.example/alternate"},
			"tech":    {ID: "tech", Type: "Organization", Key: "synthetic-acme-tech"},
			"parent":  {ID: "parent", Type: "Organization", Key: "synthetic-acme-holdings"},
			"sibling": {ID: "sibling", Type: "Organization", Key: "synthetic-acme-europe"},
		},
		links: []Relation{
			{ID: "d1", FromID: "u1", ToID: "f", Label: "domain", Type: "SimpleRelation"},
			{ID: "d2", FromID: "u2", ToID: "f", Label: "domain", Type: "SimpleRelation"},
			{ID: "w1", FromID: "tech", ToID: "u1", Label: "website", Type: "SimpleRelation"},
			{ID: "w2", FromID: "tech", ToID: "u2", Label: "website", Type: "SimpleRelation"},
			{ID: "s1", FromID: "parent", ToID: "tech", Label: "subsidiary", Type: "SimpleRelation"},
			{ID: "s2", FromID: "parent", ToID: "sibling", Label: "subsidiary", Type: "SimpleRelation"},
		},
		evidence: map[string][]Evidence{
			"d1": {{ID: "d1-a", SubjectID: "d1", SourceID: "dns-a", Kind: "SourceProperty"}},
			"w1": {{ID: "w1-a", SubjectID: "w1", SourceID: "website-a", Kind: "SourceProperty"}},
			"d2": {{ID: "d2-a", SubjectID: "d2", SourceID: "dns-a", Kind: "SourceProperty"},
				{ID: "d2-b", SubjectID: "d2", SourceID: "dns-b", Kind: "SourceProperty"}},
			"w2": {{ID: "w2-a", SubjectID: "w2", SourceID: "website-a", Kind: "SourceProperty"},
				{ID: "w2-b", SubjectID: "w2", SourceID: "website-b", Kind: "SourceProperty"}},
			"s1": {{ID: "s1-a", SubjectID: "s1", SourceID: "registry-a", Kind: "SourceProperty"},
				{ID: "s1-b", SubjectID: "s1", SourceID: "registry-b", Kind: "SourceProperty"}},
			"s2": {{ID: "s2-a", SubjectID: "s2", SourceID: "registry-a", Kind: "SourceProperty"}},
		},
	}
	model := &plannerModel{replies: []string{}}
	// Use the same test resolver as the other end-to-end adaptive tests.
	// fakeGraph alone supports traversal but not indexed ResolveAsset.
	resolved := plannedGraph{fakeGraph: g}
	a := Agent{Model: model, Runner: ToolRunner{Graph: resolved, Catalog: testOAMCatalog, Limits: DefaultLimits()}}
	question := "Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?"
	out, err := a.AskAdaptive(context.Background(), question,
		AdaptiveOptions{MaxDepth: 8, MaxPathsPerAsset: 3, GuidanceRounds: 0})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 0 {
		t.Fatalf("expected zero model calls, got %d", model.calls)
	}
	if out.Search == nil || len(out.Search.Matches) != 6 || out.Search.Truncated || out.Search.AlternativeMatches != 3 {
		t.Fatalf("lost alternate graph candidates: %+v", out.Search)
	}
	if out.EvidenceDossier == nil || len(out.EvidenceDossier.Paths) != 6 || out.EvidenceDossier.InspectedEdges != 6 {
		t.Fatalf("wrong full-path evidence coverage: %+v", out.EvidenceDossier)
	}
	if len(out.Matches) != 1 || out.Matches[0].Nodes[len(out.Matches[0].Nodes)-1].ID != "tech" ||
		out.Matches[0].Nodes[1].ID != "u2" {
		t.Fatalf("should select direct Acme Technologies via better tagged URL: %+v", out.Matches)
	}
	if len(out.AnswerGroups) != 3 {
		t.Fatalf("parent/sibling context lost: %+v", out.AnswerGroups)
	}

	var preferred, alternate string
	var contextual int
	for _, summary := range out.AnswerGroups {
		if summary.AssetID == "tech" {
			preferred = summary.PreferredPathID
			if len(summary.AlternativePathIDs) != 1 {
				t.Fatalf("direct alternate route not retained: %+v", summary)
			}

			alternate = summary.AlternativePathIDs[0]
		} else if !summary.DirectToGoal {
			contextual++
		}
	}
	if contextual != 2 || preferred != out.Matches[0].PathID || alternate == preferred {
		t.Fatalf("context or alternate selection wrong: %+v", out.AnswerGroups)
	}

	t.Logf("SIX PATHS: model_calls=%d candidates=%d primary=%s preferred=%s weaker=%s indirect_groups=%d",
		model.calls, len(out.Search.Matches), out.Matches[0].Nodes[2].ID, preferred, alternate, contextual)
}
