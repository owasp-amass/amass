// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"
)

// namedOrgGraph resolves organizations by exact stored name.
type namedOrgGraph struct{ plannedGraph }

func (g namedOrgGraph) ResolveOrganizations(_ context.Context, q OrganizationQuery, _ int) (OrganizationResolution,
	error) {
	result := OrganizationResolution{Query: q, Status: "not_found", Candidates: []OrganizationCandidate{}}
	for _, a := range g.assets {
		if a.Type == "Organization" && strings.EqualFold(contentString(a, "name"), q.Name) {
			result.Candidates = append(result.Candidates, OrganizationCandidate{Asset: a})
		}
	}
	if len(result.Candidates) == 1 {
		result.Status = "matched"
	}

	return result, nil
}

// groupFixture is shaped like a GLEIF-recorded group: a Luxembourg parent,
// its Swedish subsidiary, two subsidiaries of that, and a reviewed unit; an
// unrelated company shares a name word.
func groupFixture() namedOrgGraph {
	g := fakeGraph{assets: map[string]Asset{}}
	org := func(id, name, jur, reg string) {
		g.assets[id] = Asset{ID: id, Type: "Organization", Key: name, Content: map[string]any{"name": name,
			"jurisdiction": jur, "registration_id": reg}}
	}
	link := func(from, label, to string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	org("sa", "Spotify Technology S.A.", "LU", "B123052")
	org("ab", "Spotify AB", "SE", "5567037224")
	org("usa", "Spotify USA Inc.", "US-DE", "4544421")
	org("uk", "Spotify Limited", "GB", "06436047")
	org("sec", "Spotify Security", "", "")
	org("other", "Spotify Fans Club", "", "")
	link("sa", "subsidiary", "ab")
	link("ab", "subsidiary", "usa")
	link("ab", "subsidiary", "uk")
	link("ab", "org_unit", "sec")

	return namedOrgGraph{plannedGraph{fakeGraph: g}}
}

func TestFindCorporateGroup(t *testing.T) {
	g := groupFixture()
	r, err := FindCorporateGroup(context.Background(), g, g.assets["usa"])
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Tops) != 1 || r.Tops[0].ID != "sa" || r.Truncated {
		t.Fatalf("tops = %+v, truncated %v (%s)", r.Tops, r.Truncated, r.Reason)
	}
	if strings.Join(r.Labels, ",") != "org_unit,subsidiary" {
		t.Errorf("labels from the semantics table = %v", r.Labels)
	}

	depth := map[string]int{}
	for _, m := range r.Members {
		depth[m.Organization.ID] = m.Depth
	}
	want := map[string]int{"sa": 0, "ab": 1, "usa": 2, "uk": 2, "sec": 2}
	if len(depth) != len(want) {
		t.Errorf("members = %v, want %v", depth, want)
	}
	for id, d := range want {
		if got, ok := depth[id]; !ok || got != d {
			t.Errorf("%s at depth %d (present %v), want %d", id, got, ok, d)
		}
	}

	text := FormatGroupReport(r)
	for _, want := range []string{"Ultimate parent: Spotify Technology S.A.",
		"  subsidiary: Spotify AB [SE 5567037224]", "    subsidiary: Spotify USA Inc. [US-DE 4544421] <- asked about",
		"    org_unit: Spotify Security"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Fans Club") {
		t.Errorf("an unrelated company joined the group:\n%s", text)
	}
}

func TestCorporateGroupEdgeCases(t *testing.T) {
	// Two sources name different parents.
	g := groupFixture()
	g.assets["lux"] = Asset{ID: "lux", Type: "Organization", Key: "Other Parent", Content: map[string]any{
		"name": "Other Parent"}}
	g.links = append(g.links, Relation{ID: "lux-sub-ab", FromID: "lux", ToID: "ab", Label: "subsidiary",
		Type: "SimpleRelation"})
	r, err := FindCorporateGroup(context.Background(), g, g.assets["usa"])
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Tops) != 2 || !strings.Contains(FormatGroupReport(r), "Sources disagree on the ultimate parent") {
		t.Errorf("conflicting parents: tops %+v\n%s", r.Tops, FormatGroupReport(r))
	}

	// A cycle ends, and says so.
	c := groupFixture()
	c.links = append(c.links, Relation{ID: "usa-sub-sa", FromID: "usa", ToID: "sa", Label: "subsidiary",
		Type: "SimpleRelation"})
	r, err = FindCorporateGroup(context.Background(), c, c.assets["usa"])
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || !strings.Contains(r.Reason, "cycle") || len(r.Members) == 0 {
		t.Errorf("cycle: %+v", r)
	}

	// An organization with no stored corporate links.
	r, err = FindCorporateGroup(context.Background(), g, g.assets["other"])
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Members) != 1 || !strings.Contains(FormatGroupReport(r), "No parent, subsidiary or unit") {
		t.Errorf("lone organization:\n%s", FormatGroupReport(r))
	}
}

// From a domain, the group is its main organization's.
func TestCorporateGroupFromDomain(t *testing.T) {
	g := familyGraph()
	g.assets["holding"] = Asset{ID: "holding", Type: "Organization", Key: "hopkins health system",
		Content: map[string]any{"name": "hopkins health system"}}
	g.links = append(g.links, Relation{ID: "holding-sub-jhu-arin", FromID: "holding", ToID: "jhu-arin",
		Label: "subsidiary", Type: "SimpleRelation"})

	r, err := FindCorporateGroup(context.Background(), g, g.assets["jhu.edu"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Domain != "jhu.edu" || r.Subject.ID != "jhu-arin" || len(r.Tops) != 1 || r.Tops[0].ID != "holding" {
		t.Errorf("domain %q subject %s tops %+v", r.Domain, r.Subject.ID, r.Tops)
	}
}

// The planner's group answer runs the lens without another model call.
func TestAskCorporateGroup(t *testing.T) {
	g := groupFixture()
	reply := `{"subject":{"type":"Organization","field":"name","value":"Spotify USA Inc."},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"org_group","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "Who owns Spotify USA Inc.?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OrgGroupReport == nil || model.calls != 1 || !strings.Contains(res.Answer, "Ultimate parent: Spotify Technology") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}
}
