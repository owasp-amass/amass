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

func websiteRouteQuery() Query {
	return Query{
		Version:     QueryVersion,
		Subject:     PlanSubject{Type: "Organization", Name: "Acme Holdings Inc."},
		Traversal:   TraversalRoute,
		TargetTypes: []string{"URL"},
		Direction:   "both",
		Purpose:     "connected",
		Hops: []PlanHop{
			{Direction: "out", Label: "subsidiary", RelationType: "SimpleRelation", DestinationType: "Organization"},
			{Direction: "out", Label: "website", RelationType: "SimpleRelation", DestinationType: "URL"},
		},
		Source: SourceCaller,
	}
}

func TestValidateQuery(t *testing.T) {
	catalog, selectors, limits := testOAMCatalog.Relations(), testOAMCatalog.SearchFields(), DefaultLimits()
	if err := ValidateQuery(websiteRouteQuery(), catalog, selectors, limits); err != nil {
		t.Fatalf("valid route rejected: %v", err)
	}
	explore := Query{Version: QueryVersion, Subject: PlanSubject{Type: "FQDN", Field: "name", Value: "tech.acme.example"},
		Traversal: TraversalExplore, TargetTypes: []string{"Organization"}, Direction: "both", Purpose: "connected", Source: SourceCaller}
	if err := ValidateQuery(explore, catalog, selectors, limits); err != nil {
		t.Fatalf("valid explore rejected: %v", err)
	}

	bad := map[string]func(q *Query){
		"version":         func(q *Query) { q.Version = 2 },
		"traversal":       func(q *Query) { q.Traversal = "teleport" },
		"source":          func(q *Query) { q.Source = "rumour" },
		"invented label":  func(q *Query) { q.Hops[1].Label = "hosted-on" },
		"wrong target":    func(q *Query) { q.TargetTypes = []string{"Organization"} },
		"no hops":         func(q *Query) { q.Hops = nil },
		"route exclusion": func(q *Query) { q.ExcludeRoot = true },
		"route purpose":   func(q *Query) { q.Purpose = "ultimate_parent" },
		"mismatched rels": func(q *Query) {
			q.Relationships = []GoalRelation{GoalRelation(testOAMCatalog[0])}
			q.PathRule = "ordered"
		},
		"unknown subject": func(q *Query) { q.Subject = PlanSubject{Type: "Spaceship", Field: "name", Value: "x"} },
		"mixed org selector": func(q *Query) {
			q.Subject = PlanSubject{Type: "FQDN", Field: "name", Value: "a.example", Name: "Acme"}
		},
	}
	for name, mutate := range bad {
		q := websiteRouteQuery()
		mutate(&q)
		if err := ValidateQuery(q, catalog, selectors, limits); err == nil {
			t.Errorf("%s: invalid query accepted", name)
		}
	}
	explore.Hops = websiteRouteQuery().Hops
	if err := ValidateQuery(explore, catalog, selectors, limits); err == nil {
		t.Error("explore with hops accepted")
	}
}

func TestValidateHierarchyQuery(t *testing.T) {
	cat := fqdnInventoryCatalog
	q := Query{Version: QueryVersion, Subject: PlanSubject{Type: "FQDN", Field: "name", Value: "owasp.org"},
		Traversal: TraversalHierarchy, TargetTypes: []string{"FQDN"}, Direction: "out", Purpose: "connected",
		Relationships: []GoalRelation{{SourceType: "FQDN", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"}},
		PathRule:      "all", ExcludeRoot: true, Source: SourceCaller}
	if err := ValidateQuery(q, cat.Relations(), cat.SearchFields(), DefaultLimits()); err != nil {
		t.Fatalf("valid hierarchy rejected: %v", err)
	}
	q.Direction = "both"
	if err := ValidateQuery(q, cat.Relations(), cat.SearchFields(), DefaultLimits()); err == nil {
		t.Fatal("hierarchy with direction both accepted")
	}
}

func TestCompileQuestionDeterministicRoutes(t *testing.T) {
	agent := Agent{Runner: ToolRunner{Limits: DefaultLimits(), Catalog: fqdnInventoryCatalog}}
	q, err := agent.CompileQuestion(context.Background(), "Which subdomains are associated with owasp.org?")
	if err != nil {
		t.Fatal(err)
	}
	if q.Traversal != TraversalHierarchy || !q.ExcludeRoot || q.Source != SourceFQDNHierarchy || q.Subject.Value != "owasp.org" {
		t.Fatalf("subdomain question compiled to %+v", q)
	}
	q, err = agent.CompileQuestion(context.Background(), "Which FQDN assets are associated with owasp.org?")
	if err != nil || q.Traversal != TraversalHierarchy || q.ExcludeRoot {
		t.Fatalf("FQDN inventory compiled to %+v err=%v", q, err)
	}
	// Without a model, a question no compiler recognises must fail closed.
	if _, err := agent.CompileQuestion(context.Background(), "Tell me something interesting about owasp.org"); err == nil {
		t.Fatal("unrecognised question compiled without a model")
	}
}

func TestCompileQuestionTypedRoute(t *testing.T) {
	agent := Agent{Runner: ToolRunner{Limits: DefaultLimits(), Catalog: typedIntentTestCatalog}}
	q, err := agent.CompileQuestion(context.Background(), "Which URLs are connected to tech.acme.example via domain relationships?")
	if err != nil {
		t.Fatal(err)
	}
	if q.Traversal != TraversalRoute || q.Source != SourceTypedRelation || len(q.Hops) != 1 || q.Hops[0].Label != "domain" {
		t.Fatalf("typed question compiled to %+v", q)
	}
}

func TestAskQueryRouteNeedsNoModel(t *testing.T) {
	runner := ToolRunner{Graph: examplePlannedGraph(), Limits: DefaultLimits(), Catalog: testOAMCatalog}
	out, err := (Agent{Runner: runner}).AskQuery(context.Background(), websiteRouteQuery(), AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Incomplete || len(out.Matches) != 2 || out.Query == nil || out.Query.Source != SourceCaller {
		t.Fatalf("unexpected route result: %+v", out)
	}
	for _, want := range []string{"https://tech.acme.example/", "https://eu.acme.example/"} {
		if !strings.Contains(out.Answer, want) {
			t.Errorf("answer lacks %s: %s", want, out.Answer)
		}
	}
}

func TestAskQueryExploreRequiresModelAndValidQuery(t *testing.T) {
	runner := ToolRunner{Graph: examplePlannedGraph(), Limits: DefaultLimits(), Catalog: testOAMCatalog}
	explore := QueryFromGoal(InvestigationGoal{Subject: PlanSubject{Type: "Organization", Name: "Acme Holdings Inc."},
		TargetTypes: []string{"URL"}, Direction: "both", Purpose: "connected"}, "", SourceCaller)
	if _, err := (Agent{Runner: runner}).AskQuery(context.Background(), explore, AdaptiveOptions{}); err == nil {
		t.Fatal("explore query ran without a model")
	}
	bad := websiteRouteQuery()
	bad.Hops[0].Label = "invented"
	out, err := (Agent{Runner: runner}).AskQuery(context.Background(), bad, AdaptiveOptions{})
	if err == nil || !out.Incomplete || len(out.Observations) != 0 {
		t.Fatalf("invalid query must fail before any graph access: %+v err=%v", out, err)
	}
}

func TestQueryJSONRoundTripAndDescribe(t *testing.T) {
	q := websiteRouteQuery()
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	var back Query
	if err := decodeStrict(raw, &back); err != nil {
		t.Fatalf("query JSON must decode strictly: %v", err)
	}
	if back.Traversal != q.Traversal || len(back.Hops) != 2 || back.Subject.Name != q.Subject.Name {
		t.Fatalf("round trip lost fields: %+v", back)
	}
	desc := q.Describe()
	if !strings.Contains(desc, "out subsidiary to Organization, then out website to URL") {
		t.Fatalf("unexpected description: %s", desc)
	}
}
