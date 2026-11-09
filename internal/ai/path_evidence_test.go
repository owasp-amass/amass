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

func provenancePath() PlanMatch {
	return PlanMatch{Nodes: []Asset{
		{ID: "f", Type: "FQDN", Key: "tech.acme.example"},
		{ID: "u", Type: "URL", Key: "https://tech.acme.example/"},
		{ID: "o", Type: "Organization", Key: "synthetic-tech"},
		{ID: "p", Type: "Organization", Key: "synthetic-parent"},
	}, Edges: []Relation{
		{ID: "dns", FromID: "u", ToID: "f", Label: "domain", Type: "SimpleRelation"},
		{ID: "web", FromID: "o", ToID: "u", Label: "website", Type: "SimpleRelation"},
		{ID: "ownership", FromID: "p", ToID: "o", Label: "subsidiary", Type: "SimpleRelation"},
	}}
}
func TestPathEvidenceDistinguishesSourcedFromUnsupportedLinks(t *testing.T) {
	path := provenancePath()
	graph := fakeGraph{evidence: map[string][]Evidence{
		"dns": {{ID: "dns-a", SubjectID: "dns", SourceID: "synthetic-dns-a", Kind: "SourceProperty"}},
		"web": {{ID: "web-a", SubjectID: "web", SourceID: "synthetic-site-a", Kind: "SourceProperty"},
			{ID: "web-b", SubjectID: "web", SourceID: "synthetic-site-b", Kind: "SourceProperty"}},
		"ownership": {{ID: "own-a", SubjectID: "ownership", SourceID: "synthetic-registry-a", Kind: "SourceProperty"},
			{ID: "own-b", SubjectID: "ownership", SourceID: "synthetic-lei-b", Kind: "SourceProperty"}},
	}}
	dossier, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), []PlanMatch{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(dossier.Paths) != 1 || len(dossier.Paths[0].Edges) != 3 {
		t.Fatalf("missing evidence: %+v", dossier)
	}
	if dossier.Paths[0].Status != "limited_source_support" || dossier.Paths[0].WeakestLink != "dns" {
		t.Fatalf("one weak edge must reduce entire path support: %+v", dossier.Paths[0])
	}
	if dossier.Paths[0].VerifiedOwnership {
		t.Fatal("source tags cannot verify legal ownership")
	}
	if dossier.Paths[0].Edges[0].Status != "single_source" || dossier.Paths[0].Edges[2].Status != "multiple_source_tags" {
		t.Fatalf("edge-level provenance misclassified: %+v", dossier.Paths[0].Edges)
	}
	if dossier.Truncated {
		t.Fatal("unexpected evidence truncation")
	}
	t.Logf("source support: DNS=%s website=%s subsidiary=%s path=%s", dossier.Paths[0].Edges[0].Status,
		dossier.Paths[0].Edges[1].Status, dossier.Paths[0].Edges[2].Status, dossier.Paths[0].Status)
}

func TestPathEvidenceDoesNotMistakeGenericTagsForIndependentSources(t *testing.T) {
	path := provenancePath()
	graph := fakeGraph{evidence: map[string][]Evidence{
		"dns": {{ID: "tag1", SubjectID: "dns", Kind: "SimpleProperty"},
			{ID: "tag2", SubjectID: "dns", Kind: "SimpleProperty"}},
		"web": {{ID: "tag3", SubjectID: "web", SourceID: "same-upstream", Kind: "SourceProperty"},
			{ID: "tag4", SubjectID: "web", SourceID: "same-upstream", Kind: "SourceProperty"}},
	}}
	dossier, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), []PlanMatch{path})
	if err != nil {
		t.Fatal(err)
	}
	if dossier.Paths[0].Edges[0].Status != "no_attributed_sources" || dossier.Paths[0].Edges[0].UnattributedTags != 2 {
		t.Fatalf("unattributed tags incorrectly counted as independent sources: %+v", dossier.Paths[0].Edges[0])
	}
	if len(dossier.Paths[0].Edges[1].AttributedSources) != 1 || dossier.Paths[0].Edges[1].Status != "single_source" {
		t.Fatalf("repeated same source incorrectly corroborated: %+v", dossier.Paths[0].Edges[1])
	}
	if dossier.Paths[0].Edges[2].Status != "no_attributed_sources" {
		t.Fatal("missing edge provenance must be explicitly reported")
	}
}

func TestPathEvidenceRejectsMisattachedSourceTags(t *testing.T) {
	graph := fakeGraph{evidence: map[string][]Evidence{
		"dns": {{ID: "tag", SubjectID: "not-dns", SourceID: "synthetic-incorrect", Kind: "SourceProperty"}},
	}}
	_, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), []PlanMatch{provenancePath()})
	if err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("tag assigned to wrong relation was accepted: %v", err)
	}
}

func TestPathEvidenceReportsLookupBudgetAndNoFictitiousCoverage(t *testing.T) {
	p := PlanMatch{}
	graph := fakeGraph{evidence: map[string][]Evidence{}}
	for i := 0; i <= 42; i++ {
		p.Nodes = append(p.Nodes, Asset{ID: fmt.Sprintf("n%d", i), Type: "FQDN"})
	}
	for i := 0; i < 42; i++ {
		p.Edges = append(p.Edges, Relation{ID: fmt.Sprintf("e%d", i), FromID: p.Nodes[i].ID, ToID: p.Nodes[i+1].ID, Label: "test"})
	}
	dossier, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), []PlanMatch{p})
	if err != nil {
		t.Fatal(err)
	}
	if !dossier.Truncated || dossier.InspectedEdges != 40 || dossier.Paths[0].Status != "limited_source_support" {
		t.Fatalf("edge budget was not observed: %+v", dossier)
	}
	if dossier.Paths[0].Edges[40].Status != "not_assessed" || !dossier.Paths[0].Edges[40].Truncated {
		t.Fatalf("unexamined edge must not count as assessed: %+v", dossier.Paths[0].Edges[40])
	}
}

func TestPathEvidenceReportsPerEdgeRecordTruncation(t *testing.T) {
	graph := fakeGraph{evidence: map[string][]Evidence{}}
	for i := 0; i < 10; i++ {
		graph.evidence["dns"] = append(graph.evidence["dns"], Evidence{ID: fmt.Sprintf("t%d", i), SubjectID: "dns", SourceID: fmt.Sprintf("src%d", i), Kind: "SourceProperty"})
	}
	dossier, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), []PlanMatch{provenancePath()})
	if err != nil {
		t.Fatal(err)
	}
	if !dossier.Truncated || len(dossier.Paths[0].Edges[0].Records) != 8 || !dossier.Paths[0].Edges[0].Truncated {
		t.Fatalf("per-edge source limit not enforced: %+v", dossier)
	}
}
