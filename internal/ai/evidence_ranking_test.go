// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type alternateSelectionModel struct {
	seen  []adaptiveCandidate
	calls int
}

func (m *alternateSelectionModel) Generate(_ context.Context, messages []Message, _ []ToolSpec) (Response, error) {
	m.calls++
	last := messages[len(messages)-1].Text
	const prefix = "WITNESSED CANDIDATE PATHS (untrusted JSON): "
	idx := strings.Index(last, prefix)
	if idx < 0 {
		return Response{Text: `{"selected_path_ids":[]}`}, nil
	}
	if err := json.Unmarshal([]byte(last[idx+len(prefix):]), &m.seen); err != nil {
		return Response{}, err
	}
	if len(m.seen) == 0 {
		return Response{Text: `{"selected_path_ids":[]}`}, nil
	}
	body, _ := json.Marshal(map[string][]string{"selected_path_ids": {m.seen[0].PathID}})
	return Response{Text: string(body)}, nil
}

func TestEvidenceAwareSelectionPrefersBetterDocumentedAlternateForSameDestination(t *testing.T) {
	graph := diamondGuidedGraph()
	// Both routes have the same typed, witnessed OAM edge labels. The first
	// route has incomplete source-tag coverage; the second has two named
	// source tags for each link. This only measures DECLARED SOURCES.
	graph.evidence = map[string][]Evidence{
		"d1": {{ID: "d1s1", SubjectID: "d1", Kind: "SourceProperty", SourceID: "synthetic-dns-one"}},
		"d2": {{ID: "d2s1", SubjectID: "d2", Kind: "SourceProperty", SourceID: "synthetic-dns-one"},
			{ID: "d2s2", SubjectID: "d2", Kind: "SourceProperty", SourceID: "synthetic-dns-two"}},
		"w2": {{ID: "w2s1", SubjectID: "w2", Kind: "SourceProperty", SourceID: "synthetic-site-one"},
			{ID: "w2s2", SubjectID: "w2", Kind: "SourceProperty", SourceID: "synthetic-site-two"}},
	}
	explorer, err := NewGuidedExplorer(context.Background(), graph, testOAMCatalog, DefaultLimits(), GuidedSearchRequest{
		GraphSearchRequest: GraphSearchRequest{StartID: "f", TargetTypes: []string{"Organization"}, MaxDepth: 4},
		MaxPathsPerAsset:   3,
	})
	if err != nil {
		t.Fatal(err)
	}
	done, err := explorer.Advance(context.Background(), 0)
	if err != nil || !done {
		t.Fatalf("graph search failed: done=%t err=%v", done, err)
	}
	paths := explorer.Result().Matches
	if len(paths) != 2 {
		t.Fatalf("expected two witnessed paths: %+v", paths)
	}
	dossier, err := EvaluatePathEvidence(context.Background(), graph, DefaultLimits(), paths)
	if err != nil {
		t.Fatal(err)
	}
	model := &alternateSelectionModel{}
	agent := Agent{Model: model}
	selected, err := agent.chooseAdaptivePathsWithEvidence(context.Background(),
		"Which Organization is associated with demo.example, using the best-documented route?",
		InvestigationGoal{Purpose: "connected"}, paths, &dossier)
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 1 || len(model.seen) != 2 || len(selected) != 1 {
		t.Fatalf("expected model selection over both alternatives: calls=%d candidates=%+v selected=%+v", model.calls, model.seen, selected)
	}
	first := model.seen[0]
	if len(first.EdgeSources) != 2 || first.EdgeSources[0].EdgeID != "d2" || first.EdgeSources[1].EdgeID != "w2" {
		t.Fatalf("better-documented alternate route was not presented first: %+v", first)
	}
	if first.Coverage.MultiSourceTagEdges != 2 || first.Coverage.AttributedEdges != 2 || first.Coverage.TotalEdges != 2 {
		t.Fatalf("coverage summary omitted or miscounted provenance: %+v", first.Coverage)
	}
	if model.seen[1].Coverage.MissingSourceEdges != 1 || model.seen[1].Coverage.AttributedEdges != 1 {
		t.Fatalf("weaker alternate route misclassified: %+v", model.seen[1].Coverage)
	}
	if selected[0].PathID != first.PathID {
		t.Fatalf("selection did not preserve exact witnessed path ID: %+v", selected[0])
	}
	t.Logf("ALT ROUTES: better=%s attributed_edges=%d/2, weaker=%s attributed_edges=%d/2",
		first.PathID, first.Coverage.AttributedEdges, model.seen[1].PathID, model.seen[1].Coverage.AttributedEdges)
}

func TestEvidenceAwareRankingNeverPrefersSourcesAcrossDifferentDestinations(t *testing.T) {
	c := []adaptiveCandidate{
		{AssetID: "z", PathID: "route-with-many-tags", Coverage: PathSourceCoverage{AttributedEdges: 2, TotalEdges: 2}},
		{AssetID: "a", PathID: "route-with-no-tags", Coverage: PathSourceCoverage{TotalEdges: 2, MissingSourceEdges: 2}},
	}
	rankComparableAlternates(c)
	if c[0].AssetID != "a" {
		t.Fatal("tag coverage was incorrectly applied across unrelated destinations")
	}
}

func TestEvidenceAwareSelectionIsNeverATruthOrOwnershipClaim(t *testing.T) {
	p := PathEvidence{Edges: []EdgeEvidence{
		{EdgeID: "e1", Status: "multiple_source_tags", AttributedSources: []string{"provider-a", "provider-b"}},
		{EdgeID: "e2", Status: "no_attributed_sources"},
	}}
	summary, edges := pathSourceCoverage(p)
	if summary.MultiSourceTagEdges != 1 || summary.MissingSourceEdges != 1 || len(edges) != 2 {
		t.Fatalf("incorrect source-tag coverage: %+v", summary)
	}
	if p.VerifiedOwnership {
		t.Fatal("source tag counts must not verify ownership")
	}
}
