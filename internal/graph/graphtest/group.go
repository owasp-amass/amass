// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"context"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// namedOrgGraph resolves organizations by exact stored name.
type namedOrgGraph struct{ PlannedGraph }

func (g namedOrgGraph) ResolveOrganizations(_ context.Context, q graph.OrganizationQuery, _ int) (graph.OrganizationResolution,
	error) {
	result := graph.OrganizationResolution{Query: q, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	for _, a := range g.Assets {
		if a.Type == "Organization" && strings.EqualFold(graph.ContentString(a, "name"), q.Name) {
			result.Candidates = append(result.Candidates, graph.OrganizationCandidate{Asset: a})
		}
	}
	if len(result.Candidates) == 1 {
		result.Status = "matched"
	}

	return result, nil
}

// GroupFixture is shaped like a GLEIF-recorded group: a Luxembourg parent,
// its Swedish subsidiary, two subsidiaries of that, and a reviewed unit; an
// unrelated company shares a name word.
func GroupFixture() namedOrgGraph {
	g := FakeGraph{Assets: map[string]graph.Asset{}}
	org := func(id, name, jur, reg string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Organization", Key: name, Content: map[string]any{"name": name,
			"jurisdiction": jur, "registration_id": reg}}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
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

	return namedOrgGraph{PlannedGraph{FakeGraph: g}}
}
