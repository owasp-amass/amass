// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

func sampleReport() lens.RelationReport {
	return lens.RelationReport{
		Kind: "org_unit",
		Candidates: []lens.RelationCandidate{{
			FromID:     "org-parent",
			From:       "State University of New York",
			Label:      "org_unit",
			ToID:       "org-unit",
			To:         "SUNY Polytechnic Institute",
			Confidence: 70,
			Signals:    []string{"acronym expansion", "shared address"},
			Witness: []graph.WitnessEdge{{
				EdgeID: "e1", Label: "street_address", FromID: "org-parent", ToID: "loc-1",
			}},
		}},
	}
}

func TestRelationProposalIDStableAndDirectional(t *testing.T) {
	a := RelationProposalID("org_unit", "org-parent", "org_unit", "org-unit")
	b := RelationProposalID("org_unit", "org-parent", "org_unit", "org-unit")
	if a != b {
		t.Fatalf("ID is not stable: %s vs %s", a, b)
	}
	if got := RelationProposalID("org_unit", "org-unit", "org_unit", "org-parent"); got == a {
		t.Error("ID must be directional: reversed endpoints produced the same ID")
	}
	if !IsRelationProposal(a, "org_unit") || IsRelationProposal(a, "horizontal") {
		t.Errorf("prefix check wrong for %s", a)
	}
}

func TestRelationProposalsFromReport(t *testing.T) {
	ps := RelationProposals(sampleReport())
	if len(ps) != 1 {
		t.Fatalf("want 1 proposal, got %d", len(ps))
	}
	p := ps[0]
	if p.Kind != "org_unit" || p.Label != "org_unit" || p.FromID != "org-parent" || p.ToID != "org-unit" {
		t.Errorf("fields not carried: %+v", p)
	}
	if p.Confidence != 70 || len(p.Signals) != 2 || len(p.Witness) != 1 || p.Status != ProposalPending {
		t.Errorf("confidence/signals/witness/status not carried: %+v", p)
	}

	// An incomplete candidate (no To) is dropped.
	bad := lens.RelationReport{Kind: "k", Candidates: []lens.RelationCandidate{{FromID: "a", Label: "l"}}}
	if got := RelationProposals(bad); len(got) != 0 {
		t.Errorf("incomplete candidate should be dropped, got %d", len(got))
	}
}

func TestSubmitRelationsDedup(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	ps := RelationProposals(sampleReport())

	added, err := j.SubmitRelations(ps)
	if err != nil || len(added) != 1 {
		t.Fatalf("first submit: added %d, err %v", len(added), err)
	}
	again, err := j.SubmitRelations(ps)
	if err != nil || len(again) != 0 {
		t.Fatalf("resubmit should add nothing: added %d, err %v", len(again), err)
	}
}

func TestPendingAppliedRetractLifecycle(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	p := RelationProposals(sampleReport())[0]
	if _, err := j.SubmitRelations([]RelationProposal{p}); err != nil {
		t.Fatal(err)
	}

	// Pending before a decision.
	if _, err := j.PendingRelation(p.ID); err != nil {
		t.Fatalf("expected pending: %v", err)
	}

	w := newFakeRelationStore("org-parent", "org-unit")
	edgeID, err := ApplyRelation(ctx, w, j, p, "jeff")
	if err != nil || edgeID == "" {
		t.Fatalf("apply: edge %q err %v", edgeID, err)
	}
	if !w.hasEdge(edgeID) {
		t.Error("apply did not create the edge")
	}
	// No longer pending; now applied with the recorded edge id.
	if _, err := j.PendingRelation(p.ID); err == nil {
		t.Error("applied proposal should not be pending")
	}
	if _, got, err := j.AppliedRelation(p.ID); err != nil || got != edgeID {
		t.Errorf("AppliedRelation edge = %q (want %q), err %v", got, edgeID, err)
	}

	// Retract deletes the edge and records it.
	if err := RetractRelation(ctx, w, j, p.ID, "jeff"); err != nil {
		t.Fatalf("retract: %v", err)
	}
	if w.hasEdge(edgeID) {
		t.Error("retract did not delete the edge")
	}
	if _, _, err := j.AppliedRelation(p.ID); err == nil {
		t.Error("retracted proposal should no longer report as applied")
	}
}

// fakeRelationStore is an in-memory RelationApplier/RelationDeleter for tests.
type fakeRelationStore struct {
	ents  map[string]*dbt.Entity
	edges map[string]*dbt.Edge
	n     int
}

func newFakeRelationStore(ids ...string) *fakeRelationStore {
	s := &fakeRelationStore{ents: map[string]*dbt.Entity{}, edges: map[string]*dbt.Edge{}}
	for _, id := range ids {
		s.ents[id] = &dbt.Entity{ID: id}
	}
	return s
}

func (s *fakeRelationStore) hasEdge(id string) bool { _, ok := s.edges[id]; return ok }

func (s *fakeRelationStore) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	if e, ok := s.ents[id]; ok {
		return e, nil
	}
	return nil, nil
}

func (s *fakeRelationStore) CreateEdge(_ context.Context, e *dbt.Edge) (*dbt.Edge, error) {
	s.n++
	e.ID = "edge-" + itoa(s.n)
	s.edges[e.ID] = e
	return e, nil
}

func (s *fakeRelationStore) CreateEdgeProperty(_ context.Context, _ *dbt.Edge, _ oam.Property) (*dbt.EdgeTag, error) {
	return &dbt.EdgeTag{}, nil
}

func (s *fakeRelationStore) DeleteEdge(_ context.Context, id string) error {
	delete(s.edges, id)
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
