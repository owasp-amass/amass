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

type planCatalog []RelationshipSchema

func (c planCatalog) Relations() []RelationshipSchema { return c }

func (c planCatalog) SearchFields() []AssetSearchSchema {
	return []AssetSearchSchema{
		{Type: "Organization", Fields: []string{"name", "legal_name", "unique_id"}},
		{Type: "URL", Fields: []string{"url"}},
		{Type: "FQDN", Fields: []string{"name"}},
	}
}

var testOAMCatalog = planCatalog{
	{SourceType: "Organization", Label: "subsidiary", RelationType: "SimpleRelation", DestinationType: "Organization"},
	{SourceType: "Organization", Label: "website", RelationType: "SimpleRelation", DestinationType: "URL"},
	{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
}

type plannedGraph struct{ fakeGraph }

func (g plannedGraph) LookupOrganizations(_ context.Context, name string, _ int) ([]Asset, error) {
	if name != "Acme Holdings Inc." {
		return []Asset{}, nil
	}

	return []Asset{g.assets["parent"]}, nil
}

func (g plannedGraph) ResolveAsset(_ context.Context, selector AssetSelector, _ int) (AssetResolution, error) {
	result := AssetResolution{Query: selector, Status: "not_found", Candidates: []OrganizationCandidate{}}
	for _, asset := range g.assets {
		if asset.Type != selector.Type {
			continue
		}
		if selector.EntityID == asset.ID ||
			selector.Type == "URL" && selector.Field == "url" && selector.Value == asset.Key ||
			selector.Type == "FQDN" && selector.Field == "name" && selector.Value == asset.Key {
			result.Candidates = append(result.Candidates,
				OrganizationCandidate{
					Asset:   asset,
					Matches: []ResolutionMatch{{Field: selector.Field, Value: selector.Value}},
				})
		}
	}
	if len(result.Candidates) == 1 {
		result.Status = "matched"
	} else if len(result.Candidates) > 1 {
		result.Status = "ambiguous"
	}

	return result, nil
}

func (g plannedGraph) ResolveOrganizations(_ context.Context, q OrganizationQuery, _ int) (OrganizationResolution, error) {
	result := OrganizationResolution{Query: q, Status: "not_found", Candidates: []OrganizationCandidate{}}
	if q.Name == "Acme Holdings Inc." || q.LegalName == "Acme Holdings Inc." ||
		q.UniqueID == "synthetic-acme-holdings" {
		result.Status = "matched"
		result.Candidates = []OrganizationCandidate{
			{Asset: g.assets["parent"], Matches: []ResolutionMatch{{Field: "name", Value: "Acme Holdings Inc."}}},
		}
	}

	return result, nil
}

func examplePlannedGraph() plannedGraph {
	return plannedGraph{fakeGraph{
		assets: map[string]Asset{
			"parent": {
				ID:      "parent",
				Type:    "Organization",
				Key:     "synthetic-acme-holdings",
				Content: map[string]any{"name": "Acme Holdings Inc."},
			},
			"tech": {
				ID:      "tech",
				Type:    "Organization",
				Key:     "synthetic-acme-tech",
				Content: map[string]any{"name": "Acme Technologies Ltd."},
			},
			"europe": {
				ID:      "europe",
				Type:    "Organization",
				Key:     "synthetic-acme-europe",
				Content: map[string]any{"name": "Acme Europe GmbH"},
			},
			"website-tech": {
				ID:      "website-tech",
				Type:    "URL",
				Key:     "https://tech.acme.example/",
				Content: map[string]any{"url": "https://tech.acme.example/"},
			},
			"website-europe": {
				ID:      "website-europe",
				Type:    "URL",
				Key:     "https://eu.acme.example/",
				Content: map[string]any{"url": "https://eu.acme.example/"},
			},
			"fqdn-tech": {
				ID:      "fqdn-tech",
				Type:    "FQDN",
				Key:     "tech.acme.example",
				Content: map[string]any{"name": "tech.acme.example"},
			},
		},
		links: []Relation{
			{ID: "e1", FromID: "parent", ToID: "tech", Label: "subsidiary", Type: "SimpleRelation"},
			{ID: "e2", FromID: "parent", ToID: "europe", Label: "subsidiary", Type: "SimpleRelation"},
			{ID: "e3", FromID: "tech", ToID: "website-tech", Label: "website", Type: "SimpleRelation"},
			{ID: "e4", FromID: "europe", ToID: "website-europe", Label: "website", Type: "SimpleRelation"},
			{ID: "e5", FromID: "website-tech", ToID: "fqdn-tech", Label: "domain", Type: "SimpleRelation"},
		},
	}}
}

type plannerModel struct {
	calls   int
	replies []string
}

func (m *plannerModel) Generate(_ context.Context, _ []Message, specs []ToolSpec) (Response, error) {
	if len(specs) > 0 {
		return Response{}, nil
	}

	i := m.calls
	m.calls++
	if i >= len(m.replies) {
		i = len(m.replies) - 1
	}

	return Response{Text: m.replies[i]}, nil
}

type inspectingPlannerModel struct {
	calls    int
	requests [][]Message
	replies  []string
}

func (m *inspectingPlannerModel) Generate(_ context.Context, messages []Message, _ []ToolSpec) (Response, error) {
	m.requests = append(m.requests, append([]Message{}, messages...))
	i := m.calls
	m.calls++
	if i >= len(m.replies) {
		i = len(m.replies) - 1
	}

	return Response{Text: m.replies[i]}, nil
}

// routeQuery builds a caller-supplied route Query, the replacement for the
// retired hop planner's plans.
func routeQuery(subject PlanSubject, hops ...PlanHop) Query {
	return Query{
		Version:     QueryVersion,
		Subject:     subject,
		Traversal:   TraversalRoute,
		TargetTypes: []string{hops[len(hops)-1].DestinationType},
		Direction:   "both",
		Purpose:     "connected",
		Hops:        hops,
		Source:      SourceCaller,
	}
}

func hop(direction, label, destination string) PlanHop {
	return PlanHop{Direction: direction, Label: label, RelationType: "SimpleRelation", DestinationType: destination}
}

func askRoute(t *testing.T, q Query) Investigation {
	t.Helper()

	runner := ToolRunner{Graph: examplePlannedGraph(), Limits: DefaultLimits(), Catalog: testOAMCatalog}
	out, err := (Agent{Runner: runner}).AskQuery(context.Background(), q, AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func TestRouteMultiHopReturnsBothWebsites(t *testing.T) {
	out := askRoute(t, routeQuery(PlanSubject{Type: "Organization", Name: "Acme Holdings Inc."},
		hop("out", "subsidiary", "Organization"), hop("out", "website", "URL")))
	if out.Incomplete || len(out.Matches) != 2 {
		t.Fatalf("unexpected route result: %+v", out)
	}
	for _, s := range []string{"https://tech.acme.example/", "https://eu.acme.example/"} {
		if !strings.Contains(out.Answer, s) {
			t.Errorf("missing %q from answer: %s", s, out.Answer)
		}
	}
}

func TestRouteUnknownOrganizationIsIncompleteNotError(t *testing.T) {
	out := askRoute(t, routeQuery(PlanSubject{Type: "Organization", Name: "Unknown Corp."},
		hop("out", "subsidiary", "Organization")))
	if !out.Incomplete || !strings.Contains(out.Answer, "No asset matched") {
		t.Fatalf("no-match response: %+v", out)
	}
}

func TestRouteFQDNRootAndIncomingURLDomainEdge(t *testing.T) {
	out := askRoute(t, routeQuery(PlanSubject{Type: "FQDN", Field: "name", Value: "tech.acme.example"},
		hop("in", "domain", "URL")))
	if out.Incomplete || len(out.Matches) != 1 || out.Matches[0].Nodes[1].Key != "https://tech.acme.example/" {
		t.Fatalf("FQDN root error: %+v", out)
	}
	if out.AssetResolution == nil || out.AssetResolution.Status != "matched" {
		t.Fatalf("missing typed root resolution: %+v", out.AssetResolution)
	}
}

func TestRouteURLRootAndOutgoingDomainEdge(t *testing.T) {
	out := askRoute(t, routeQuery(PlanSubject{Type: "URL", Field: "url", Value: "https://tech.acme.example/"},
		hop("out", "domain", "FQDN")))
	if out.Incomplete || len(out.Matches) != 1 || out.Matches[0].Nodes[1].Key != "tech.acme.example" {
		t.Fatalf("URL root error: %+v", out)
	}
}

func TestRouteIntermediateHopWithoutEdgesIsExplained(t *testing.T) {
	// eu.acme.example has no domain edge, so the second hop never runs.
	out := askRoute(t, routeQuery(PlanSubject{Type: "URL", Field: "url", Value: "https://eu.acme.example/"},
		hop("out", "domain", "FQDN"), hop("in", "domain", "URL")))
	if len(out.Matches) != 0 {
		t.Fatalf("unexpected matches: %+v", out.Matches)
	}
	for _, want := range []string{"first empty relationship hop was 1", "subsequent hop(s) were not evaluated",
		"does not prove"} {
		if !strings.Contains(out.Answer, want) {
			t.Errorf("answer lacks %q: %s", want, out.Answer)
		}
	}
}

func TestRouteSingleHopNoMatchIsNotTruncated(t *testing.T) {
	out := askRoute(t, routeQuery(PlanSubject{Type: "URL", Field: "url", Value: "https://eu.acme.example/"},
		hop("out", "domain", "FQDN")))
	if out.Incomplete || len(out.Matches) != 0 {
		t.Fatalf("single-hop empty search misclassified: %+v", out)
	}
}

const urlGoal = `{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["URL"],` +
	`"direction":"both","purpose":"connected","relationships":[],"path_rule":""}`

func compileWith(t *testing.T, model Model, question string) (Query, error) {
	t.Helper()

	agent := Agent{Model: model, Runner: ToolRunner{Limits: DefaultLimits(), Catalog: testOAMCatalog}}
	return agent.CompileQuestion(context.Background(), question)
}

func TestGoalPlannerNormalizesFQDNNameToIndexedSelector(t *testing.T) {
	// Reproduces an Ollama reply that reused the Organization "name" key for
	// an FQDN; the indexed selector catalog makes the correction unambiguous.
	model := &plannerModel{replies: []string{`{"subject":{"type":"FQDN","name":"tech.acme.example"},` +
		`"target_types":["URL"],"direction":"both","purpose":"connected","relationships":[],"path_rule":""}`}}
	q, err := compileWith(t, model, "Tell me which URL assets point at the FQDN tech.acme.example")
	if err != nil || model.calls != 1 {
		t.Fatalf("normalization failed: %+v err=%v calls=%d", q, err, model.calls)
	}
	if q.Subject.Field != "name" || q.Subject.Value != "tech.acme.example" || q.Subject.Name != "" {
		t.Fatalf("subject not canonicalized: %+v", q.Subject)
	}
}

func TestGoalPlannerRetriesMissingSelectorWithFocusedGuidance(t *testing.T) {
	model := &inspectingPlannerModel{replies: []string{
		`{"subject":{"type":"FQDN"},"target_types":["URL"],"direction":"both","purpose":"connected",` +
			`"relationships":[],"path_rule":""}`,
		urlGoal,
	}}
	if _, err := compileWith(t, model, "Tell me which URL assets point at the FQDN tech.acme.example"); err != nil ||
		model.calls != 2 {
		t.Fatalf("focused retry failed: err=%v calls=%d", err, model.calls)
	}

	retry := model.requests[1][len(model.requests[1])-1].Text
	if !strings.Contains(retry, "subject.field") || !strings.Contains(retry, "subject.value") {
		t.Fatalf("retry omitted selector-specific correction: %s", retry)
	}
}

func TestGoalPlannerCorrectsUnexpectedFields(t *testing.T) {
	model := &inspectingPlannerModel{replies: []string{
		`{"subject":{"type":"URL","fields":["url"]},"target_types":["FQDN"],"direction":"both",` +
			`"purpose":"connected","relationships":[],"path_rule":""}`,
		urlGoal,
	}}
	if _, err := compileWith(t, model, "Tell me about the FQDN behind https://tech.acme.example/"); err != nil ||
		model.calls != 2 {
		t.Fatalf("retry failed: err=%v calls=%d", err, model.calls)
	}

	retry := model.requests[1][len(model.requests[1])-1].Text
	if !strings.Contains(retry, "unsupported key named fields") || !strings.Contains(retry,
		"singular field and value") {
		t.Fatalf("retry prompt not specific enough: %s", retry)
	}
}

func TestGoalParserCanonicalizesSingleFieldObject(t *testing.T) {
	goal, err := parseGoal(`{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/"}},`+
		`"target_types":["FQDN"],"direction":"both","purpose":"connected","relationships":[],"path_rule":""}`,
		testOAMCatalog.SearchFields())
	if err != nil {
		t.Fatal(err)
	}
	if goal.Subject.Type != "URL" || goal.Subject.Field != "url" || goal.Subject.Value != "https://tech.acme.example/" {
		t.Fatalf("unexpected normalized subject: %+v", goal.Subject)
	}
}

func TestGoalParserRejectsUntrustedFieldCatalogs(t *testing.T) {
	rest := `,"target_types":["FQDN"],"direction":"both","purpose":"connected","relationships":[],"path_rule":""}`
	for _, subject := range []string{
		`{"subject":{"type":"URL","fields":["url"]}`,
		`{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/","scheme":"https"}}`,
		`{"subject":{"type":"URL","fields":{"invented":"https://tech.acme.example/"}}`,
		`{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/"},"unexpected":true}`,
		`{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/"},"value":"https://elsewhere.example/"}`,
	} {
		if _, err := parseGoal(subject+rest, testOAMCatalog.SearchFields()); err == nil {
			t.Fatalf("unexpectedly accepted malformed goal: %s", subject)
		}
	}
}

func TestPlannerRejectsInventedLabelBeforeDatabaseAccess(t *testing.T) {
	p := TypedPlan{
		Subject: PlanSubject{Type: "Organization", Name: "Acme Holdings Inc."},
		Hops: []PlanHop{
			{Direction: "out", Label: "hosted-on", RelationType: "SimpleRelation", DestinationType: "URL"},
		},
	}
	if err := validatePlan(p, testOAMCatalog, DefaultLimits()); err == nil {
		t.Fatal("made-up label accepted")
	}
}

func TestSchemaCatalogTool(t *testing.T) {
	runner := ToolRunner{Graph: examplePlannedGraph(), Limits: DefaultLimits(), Catalog: testOAMCatalog}
	raw, err := runner.Run(context.Background(), "describe_oam_schema",
		json.RawMessage(`{"source_type":"Organization"}`))
	if err != nil {
		t.Fatal(err)
	}

	var rows []RelationshipSchema
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected two schema relations, got %d", len(rows))
	}
}

func TestGenericSelectorRejectsUnsupportedFields(t *testing.T) {
	if err := validatePlanWithSelectors(TypedPlan{
		Subject: PlanSubject{Type: "FQDN", Field: "domain", Value: "tech.acme.example"},
		Hops:    []PlanHop{{Direction: "in", Label: "domain", RelationType: "SimpleRelation", DestinationType: "URL"}},
	}, testOAMCatalog.Relations(), testOAMCatalog.SearchFields(), DefaultLimits()); err == nil {
		t.Fatal("unsupported FQDN selector should fail validation")
	}
}

func TestNormalizationDoesNotGuessUnsupportedSelectors(t *testing.T) {
	schema := testOAMCatalog.SearchFields()
	cases := []PlanSubject{
		{Type: "URL", Name: "https://tech.acme.example/"},
		{Type: "FQDN", Field: "url", Name: "tech.acme.example"},
		{Type: "FQDN"},
	}
	for _, candidate := range cases {
		got := normalizePlannedSubject(candidate, schema)
		if got.Field != candidate.Field || got.Value != candidate.Value ||
			got.Name != candidate.Name {
			t.Fatalf("should not infer selector for %+v, got %+v", candidate, got)
		}
	}
}

func TestCompactCatalogPreservesAllTransitions(t *testing.T) {
	rows := []RelationshipSchema{
		{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
		{
			SourceType:      "Organization",
			Label:           "subsidiary",
			RelationType:    "SimpleRelation",
			DestinationType: "Organization",
		},
		{
			SourceType:      "Organization",
			Label:           "subsidiary",
			RelationType:    "SimpleRelation",
			DestinationType: "Organization",
		},
		{SourceType: "Organization", Label: "website", RelationType: "SimpleRelation", DestinationType: "URL"},
	}
	compact := compactRelationshipCatalog(rows)
	if !strings.Contains(compact, "URL|domain|SimpleRelation|FQDN") ||
		!strings.Contains(compact, "Organization|subsidiary|SimpleRelation|Organization") {
		t.Fatalf("compact catalog dropped graph transitions: %s", compact)
	}
	if strings.Count(compact, "Organization|subsidiary|SimpleRelation|Organization") != 1 {
		t.Fatalf("duplicate transition not grouped: %s", compact)
	}

	compactAgain := compactRelationshipCatalog([]RelationshipSchema{rows[2], rows[0], rows[3], rows[1]})
	if compactAgain != compact {
		t.Fatalf("catalog output depends on relation order:\n%s\n%s", compact, compactAgain)
	}

	selector := compactSelectorCatalog([]AssetSearchSchema{
		{Type: "URL", Fields: []string{"scheme", "url"}},
		{Type: "FQDN", Fields: []string{"name"}},
	})
	if !strings.Contains(selector, "FQDN: name") || !strings.Contains(selector, "URL: scheme,url") {
		t.Fatalf("compact selectors lost type-specific fields: %s", selector)
	}
}

func TestFormattedMatchPreservesIncomingEdgeDirection(t *testing.T) {
	graph := examplePlannedGraph()
	incoming := PlanMatch{
		Nodes: []Asset{graph.assets["fqdn-tech"], graph.assets["website-tech"]},
		Edges: []Relation{
			{ID: "e5", FromID: "website-tech", ToID: "fqdn-tech", Label: "domain", Type: "SimpleRelation"},
		},
	}
	got := formatMatch(incoming)
	if !strings.Contains(got, "<--domain [edge e5]-- https://tech.acme.example/") {
		t.Fatalf("incoming graph edge rendered with wrong direction: %s", got)
	}

	outgoing := PlanMatch{
		Nodes: []Asset{graph.assets["website-tech"], graph.assets["fqdn-tech"]},
		Edges: incoming.Edges,
	}
	if got := formatMatch(outgoing); !strings.Contains(got, "--domain [edge e5]--> tech.acme.example") {
		t.Fatalf("outgoing graph edge rendered with wrong direction: %s", got)
	}
}

func TestFormattedSubjectForGenericRootWithoutMatches(t *testing.T) {
	root := PlanSubject{Type: "FQDN", Field: "name", Value: "tech.acme.example"}
	if got := formatPlanSubject(root); !strings.Contains(got, "tech.acme.example") {
		t.Fatalf("generic subject identifier omitted: %s", got)
	}
}
