// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

var realWorldFQDNInventoryNames = []string{
	"owasp.org", "20thanniversary.owasp.org", "name-virt-host.owasp.org",
	"gapps.owasp.org", "kerala.owasp.org", "calltobattle.owasp.org",
	"groups.owasp.org", "brainbreak.owasp.org", "ocms.owasp.org",
	"dev.owasp.org", "members.owasp.org", "sl.owasp.org",
	"cheatsheetseries.owasp.org", "wiki.owasp.org", "lightning.owasp.org",
	"training.owasp.org", "lists.owasp.org",
}

func fqdnInventoryFixture() plannedGraph {
	root := Asset{ID: "root", Type: "FQDN", Key: "owasp.org", Content: map[string]any{"name": "owasp.org"}}
	g := fakeGraph{assets: map[string]Asset{"root": root}}
	for i, name := range realWorldFQDNInventoryNames[1:] {
		id := fmt.Sprintf("fqdn-%02d", i)
		g.assets[id] = Asset{ID: id, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		g.links = append(g.links, Relation{ID: fmt.Sprintf("node-%02d",
			i), FromID: "root", ToID: id, Label: "node", Type: "SimpleRelation"})
	}
	// Real-world graphs also contain incoming URL/domain records and other
	// unrelated edges. They must not consume the 20-match inventory budget.
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("url-%02d", i)
		g.assets[id] = Asset{ID: id, Type: "URL", Key: "https://owasp.org/" + id}
		g.links = append(g.links,
			Relation{ID: "domain-" + id, FromID: id, ToID: "root", Label: "domain", Type: "SimpleRelation"})
	}

	return plannedGraph{fakeGraph: g}
}

var fqdnInventoryCatalog = planCatalog{
	{SourceType: "FQDN", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	{SourceType: "FQDN", Label: "dns_record", RelationType: "BasicDNSRelation", DestinationType: "IPAddress"},
}

func TestFQDNInventoryQuestionRetainsAllSeventeenNames(t *testing.T) {
	question := "Which FQDN assets are associated with owasp.org?"
	model := &plannerModel{}
	agent := Agent{Model: model, Runner: ToolRunner{
		Graph: fqdnInventoryFixture(), Catalog: fqdnInventoryCatalog, Limits: DefaultLimits(),
	}}
	result, err := agent.AskAdaptive(context.Background(), question, AdaptiveOptions{GuidanceRounds: 2})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 0 {
		t.Fatalf("inventory query must not invoke planner, navigator or selection LLM, calls=%d", model.calls)
	}
	if result.Goal == nil || result.Goal.Subject.Type != "FQDN" || result.Goal.Subject.Value != "owasp.org" {
		t.Fatalf("wrong deterministic goal: %+v", result.Goal)
	}
	if result.Search == nil || result.Search.Truncated || !result.Search.Exhausted || result.Incomplete {
		t.Fatalf("fully indexed node hierarchy must not truncate: %+v", result.Search)
	}
	if result.Search.Mode != "fqdn_inventory" || len(result.Matches) != 16 || len(result.AnswerGroups) != 16 {
		t.Fatalf("expected all 16 descendants and their 16 witnessed node paths: matches=%d groups=%d search=%+v",
			len(result.Matches), len(result.AnswerGroups), result.Search)
	}
	for _, name := range realWorldFQDNInventoryNames {
		if !strings.Contains(result.Answer, "\n"+name+"\n") && !strings.HasSuffix(result.Answer, "\n"+name) {
			// Every listed inventory name is on its own output line.
			// The postscript may follow the final name.
			if !strings.Contains(result.Answer, "\n"+name+"\n") {
				t.Errorf("missing FQDN %q: %q", name, result.Answer)
			}
		}
	}
	if !strings.Contains(result.Answer, "Found 17 FQDN asset(s)") {
		t.Fatalf("wrong name count: %s", result.Answer)
	}
	for _, m := range result.Matches {
		if len(m.Edges) != 1 || m.Edges[0].Label != "node" || m.Edges[0].FromID != "root" {
			t.Fatalf("nonhierarchical or unwitnessed path: %+v", m)
		}
	}
	if result.EvidenceDossier == nil || len(result.EvidenceDossier.Paths) != 16 {
		t.Fatalf("missing provenance paths: %+v", result.EvidenceDossier)
	}
}

func TestFQDNInventoryReportsPartialNamesAtConfiguredLimit(t *testing.T) {
	model := &plannerModel{}
	agent := Agent{
		Model:  model,
		Runner: ToolRunner{Graph: fqdnInventoryFixture(), Catalog: fqdnInventoryCatalog, Limits: DefaultLimits()},
	}
	result, err := agent.AskAdaptive(context.Background(),
		"Which FQDN assets are associated with owasp.org?",
		AdaptiveOptions{MaxMatches: 5, GuidanceRounds: 0})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 0 {
		t.Fatal("bounded inventory called LLM")
	}
	if result.Search == nil || !result.Search.Truncated || result.Search.Reason != "match limit" ||
		len(result.Matches) != 5 || !result.Incomplete {
		t.Fatalf("partial inventory was not transparently reported: %+v", result)
	}
	if !strings.Contains(result.Answer, "Found 6 FQDN asset(s)") || !strings.Contains(result.Answer,
		"Results are partial") {
		t.Fatalf("bounded inventory must return witnessed matches, not an empty answer: %s", result.Answer)
	}
}

func TestFQDNInventoryFastPathRejectsAmbiguousQuestions(t *testing.T) {
	for _, q := range []string{
		"Which FQDN assets are associated with owasp.org and example.net?",
		"Which FQDN assets belong to OWASP?",
		"Which organizations are associated with owasp.org?",
		"Which FQDN assets are connected to https://owasp.org?",
		"What FQDNs are related to user@owasp.org?",
	} {
		if _, ok := deterministicFQDNInventoryGoal(q, fqdnInventoryCatalog); ok {
			t.Errorf("ambiguous query bypassed semantic planner: %s", q)
		}
	}
}

func TestSubdomainIntentUsesHierarchyAndExcludesApex(t *testing.T) {
	for _, question := range []string{
		"Which subdomains are under owasp.org?",
		"Which subdomains are associated with owasp.org?",
		"List subdomains of owasp.org",
	} {
		model := &plannerModel{}
		agent := Agent{Model: model, Runner: ToolRunner{
			Graph: fqdnInventoryFixture(), Catalog: fqdnInventoryCatalog, Limits: DefaultLimits(),
		}}
		result, err := agent.AskAdaptive(context.Background(), question, AdaptiveOptions{})
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		if model.calls != 0 || result.Search == nil || result.Search.Truncated ||
			len(result.Matches) != 16 || result.Incomplete {
			t.Fatalf("%q: subdomain inventory did not use complete deterministic node hierarchy: %+v", question, result)
		}
		if !strings.Contains(result.Answer, "Found 16 subdomain FQDN asset(s)") ||
			strings.Contains(result.Answer, "\nowasp.org\n") ||
			!strings.Contains(result.Answer, "\nwiki.owasp.org\n") {
			t.Fatalf("%q: expected 16 descendants without apex: %s", question, result.Answer)
		}
	}
}

// largeFQDNInventoryFixture models a campus namespace: 150 direct
// subdomains plus 50 under cslab, more than the model-context node,
// per-node and find limits allow.
func largeFQDNInventoryFixture() plannedGraph {
	root := Asset{ID: "root", Type: "FQDN", Key: "colgate.edu", Content: map[string]any{"name": "colgate.edu"}}
	g := fakeGraph{assets: map[string]Asset{"root": root}}
	add := func(id, name, parent string) {
		g.assets[id] = Asset{ID: id, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		g.links = append(g.links, Relation{ID: "node-" + id, FromID: parent, ToID: id, Label: "node",
			Type: "SimpleRelation"})
	}

	add("cslab", "cslab.colgate.edu", "root")
	for i := 0; i < 149; i++ {
		add(fmt.Sprintf("host-%03d", i), fmt.Sprintf("host%03d.colgate.edu", i), "root")
	}
	for i := 0; i < 50; i++ {
		add(fmt.Sprintf("lab-%02d", i), fmt.Sprintf("lab%02d.cslab.colgate.edu", i), "cslab")
	}

	return plannedGraph{fakeGraph: g}
}

func TestSubdomainInventoryWordingsCompileWithoutModel(t *testing.T) {
	for _, q := range []string{
		"What are all the subdomains within colgate.edu?",
		"What are the subdomains in colgate.edu",
		"Which subdomains are in colgate.edu?",
		"List all of the subdomains under colgate.edu",
		"Show the hostnames within colgate.edu's DNS namespace",
		"Give me all subdomains of colgate.edu?",
	} {
		goal, ok := deterministicFQDNInventoryGoal(q, fqdnInventoryCatalog)
		if !ok || goal.Subject.Value != "colgate.edu" {
			t.Errorf("%q was not compiled as an inventory of colgate.edu: %+v", q, goal)
		}
	}
}

func TestLargeSubdomainInventoryIsCompleteAndSkipsModel(t *testing.T) {
	model := &plannerModel{}
	agent := Agent{Model: model, Runner: ToolRunner{
		Graph: largeFQDNInventoryFixture(), Catalog: fqdnInventoryCatalog, Limits: DefaultLimits(),
	}}

	result, err := agent.AskAdaptive(context.Background(), "What are all the subdomains within colgate.edu?",
		AdaptiveOptions{MaxMatches: 20, MaxInventory: DefaultInventoryNames, GuidanceRounds: 2})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 0 {
		t.Fatalf("inventory called the model %d time(s)", model.calls)
	}
	if result.Search == nil || result.Search.Truncated || result.Incomplete {
		t.Fatalf("inventory was truncated: %+v", result.Search)
	}
	if !strings.Contains(result.Answer, "Found 200 subdomain FQDN asset(s)") ||
		!strings.Contains(result.Answer, "\nlab49.cslab.colgate.edu\n") {
		t.Fatalf("inventory answer is missing names: %.300s", result.Answer)
	}
	if result.Diagram != "" {
		t.Fatal("inventories above the diagram limit should not render a diagram")
	}
}

func TestModelHierarchyAnswerRunsInventory(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"target_types":["FQDN"],` +
			`"direction":"both","purpose":"connected","answer":"hierarchy"}`,
	}}
	agent := Agent{Model: model, Runner: ToolRunner{
		Graph: largeFQDNInventoryFixture(), Catalog: fqdnInventoryCatalog, Limits: DefaultLimits(),
	}}

	question := "What are all the subdomains within Colgate University's DNS namespace?"
	q, err := agent.CompileQuestion(context.Background(), question)
	if err != nil {
		t.Fatal(err)
	}
	if q.Traversal != TraversalHierarchy || !q.ExcludeRoot || q.Source != SourceModelGoal {
		t.Fatalf("hierarchy answer did not compile to a hierarchy inventory: %+v", q)
	}

	result, err := agent.AskQuery(context.Background(), q, AdaptiveOptions{GuidanceRounds: 2})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 1 || result.Incomplete || !strings.Contains(result.Answer, "Found 200 subdomain") {
		t.Fatalf("calls=%d incomplete=%v answer=%.200s", model.calls, result.Incomplete, result.Answer)
	}
}

func TestModelGoalWithOtherRelationshipsIsNotPromoted(t *testing.T) {
	q := Query{
		Question: "Which FQDNs share an IP address with colgate.edu?",
		Subject:  PlanSubject{Type: "FQDN", Field: "name", Value: "colgate.edu"}, TargetTypes: []string{"FQDN"},
		Relationships: []GoalRelation{
			{SourceType: "FQDN", Label: "dns_record", RelationType: "BasicDNSRelation", DestinationType: "IPAddress"},
		},
	}
	if promoteHierarchyGoal(&q) {
		t.Fatal("a DNS record goal must not become a subdomain inventory")
	}
}
