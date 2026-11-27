// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// creatingStore also creates and deletes assets, as the repositories do.
type creatingStore struct {
	*fakeRelationStore
	created []oam.Asset
}

func (s *creatingStore) CreateAsset(_ context.Context, a oam.Asset) (*dbt.Entity, error) {
	s.created = append(s.created, a)
	e := &dbt.Entity{ID: "new-" + itoa(len(s.created)), Asset: a}
	s.ents[e.ID] = e
	return e, nil
}

func (s *creatingStore) DeleteEntity(_ context.Context, id string) error {
	delete(s.ents, id)
	return nil
}

// A proposal for a unit no source has stored creates it on approval, with
// the edge from its parent, and undoing the approval removes both.
func TestApplyRelationCreatesNewUnit(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	ps := RelationProposals(lens.RelationReport{Kind: lens.DocumentRelationKind, Candidates: []lens.RelationCandidate{{
		FromID: "org-parent", From: "Acme College", Label: "org_unit", To: "Counseling Center (new unit)",
		Confidence: 40, NewTo: &lens.NewAsset{Type: "Organization", Key: "Acme College / Counseling Center",
			Name: "Counseling Center"}}}})
	if len(ps) != 1 || ps[0].ToID != "" || ps[0].NewTo == nil {
		t.Fatalf("proposals %+v", ps)
	}
	p := ps[0]
	if _, err := j.SubmitRelations(ps); err != nil {
		t.Fatal(err)
	}

	w := &creatingStore{fakeRelationStore: newFakeRelationStore("org-parent")}
	edgeID, err := ApplyRelation(ctx, w, j, p, "jeff")
	if err != nil || !w.hasEdge(edgeID) {
		t.Fatalf("apply: edge %q, err %v", edgeID, err)
	}
	if len(w.created) != 1 {
		t.Fatalf("created %v", w.created)
	}
	o, ok := w.created[0].(*oamorg.Organization)
	if !ok || o.ID != "Acme College / Counseling Center" || o.Name != "Counseling Center" {
		t.Fatalf("created %+v", w.created[0])
	}
	if e := w.edges[edgeID]; e.FromEntity.ID != "org-parent" || e.ToEntity.ID != "new-1" {
		t.Errorf("edge %+v", e)
	}

	if err := RetractRelation(ctx, w, j, p.ID, "jeff"); err != nil {
		t.Fatal(err)
	}
	if w.hasEdge(edgeID) {
		t.Error("the edge was not removed")
	}
	if _, ok := w.ents["new-1"]; ok {
		t.Error("the created unit was not removed")
	}
}

// A store that cannot create assets cannot apply such a proposal.
func TestApplyRelationNewUnitNeedsCreator(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	p := RelationProposal{ID: "doc_relation-x", FromID: "org-parent", Label: "org_unit",
		NewTo: &lens.NewAsset{Type: "Organization", Key: "k", Name: "n"}}
	if _, err := ApplyRelation(context.Background(), newFakeRelationStore("org-parent"), j, p, "jeff"); err == nil {
		t.Fatal("applied without a way to create the unit")
	}
}
