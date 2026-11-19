// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

func TestIsRelationProposal(t *testing.T) {
	orgUnit := review.RelationProposalID("org_unit", "org-a", "org_unit", "org-b")
	horizontal := review.RelationProposalID("horizontal", "org-a", "registrant_contact", "cr-1")

	yes := []string{orgUnit, horizontal}
	for _, id := range yes {
		if !isRelationProposal(id) {
			t.Errorf("%q should be recognized as a relation proposal", id)
		}
	}

	// Every other proposal kind, and malformed IDs, must not be taken for one.
	no := []string{
		"own-0123456789abcdef",       // ownership
		"acct-0123456789abcdef",      // account
		"dup-0123456789abcdef",       // organization merge
		"pdup-0123456789abcdef",      // person merge
		"idc-0123456789abcdef",       // identity correction
		"pno-0123456789abcdef",       // organization under a person's name
		"org_unit-0123",              // too-short hash
		"org_unit-0123456789ABCDEF",  // uppercase (not lowercase hex)
		"org_unit-0123456789abcdeZ",  // non-hex digit
		"org_unit0123456789abcdef",   // no separator
		"org_unit-0123456789abcdef0", // 17 hex digits
		"",
	}
	for _, id := range no {
		if isRelationProposal(id) {
			t.Errorf("%q should not be recognized as a relation proposal", id)
		}
	}
}

// relStore is an in-memory RelationApplier/RelationDeleter for the CLI tests.
type relStore struct {
	ents  map[string]*dbt.Entity
	edges map[string]*dbt.Edge
	n     int
}

func newRelStore(ids ...string) *relStore {
	s := &relStore{ents: map[string]*dbt.Entity{}, edges: map[string]*dbt.Edge{}}
	for _, id := range ids {
		s.ents[id] = &dbt.Entity{ID: id}
	}
	return s
}

func (s *relStore) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	return s.ents[id], nil
}

func (s *relStore) CreateEdge(_ context.Context, e *dbt.Edge) (*dbt.Edge, error) {
	s.n++
	e.ID = "edge-" + strconv.Itoa(s.n)
	s.edges[e.ID] = e
	return e, nil
}

func (s *relStore) CreateEdgeProperty(_ context.Context, _ *dbt.Edge, _ oam.Property) (*dbt.EdgeTag, error) {
	return &dbt.EdgeTag{}, nil
}

func (s *relStore) DeleteEdge(_ context.Context, id string) error {
	delete(s.edges, id)
	return nil
}

// Approving a relation proposal writes its edge and records the apply; retracting
// removes the edge and records the retraction, so the proposal is no longer
// applied and the CLI wrappers report both.
func TestApproveRetractRelationCLI(t *testing.T) {
	ctx := context.Background()
	journalPath := filepath.Join(t.TempDir(), "review.jsonl")
	j := &review.Journal{Path: journalPath}

	id := review.RelationProposalID("org_unit", "org-parent", "org_unit", "org-child")
	added, err := j.SubmitRelations([]review.RelationProposal{{
		ID: id, Kind: "org_unit", FromID: "org-parent", From: "Parent Corp",
		Label: "org_unit", ToID: "org-child", To: "Child Division", Confidence: 82,
		Signals: []string{"name hierarchy", "shared address"}, Status: review.ProposalPending,
	}})
	if err != nil || len(added) != 1 {
		t.Fatalf("submit: added=%d err=%v", len(added), err)
	}

	store := newRelStore("org-parent", "org-child")

	var out bytes.Buffer
	if err := approveRelation(ctx, store, journalPath, id, "tester", &out); err != nil {
		t.Fatalf("approveRelation: %v", err)
	}
	if !strings.Contains(out.String(), "Linked") {
		t.Errorf("approve output missing confirmation: %q", out.String())
	}
	_, edgeID, err := j.AppliedRelation(id)
	if err != nil || edgeID == "" {
		t.Fatalf("proposal should be applied with an edge: edge=%q err=%v", edgeID, err)
	}
	if _, ok := store.edges[edgeID]; !ok {
		t.Errorf("edge %q should have been written to the store", edgeID)
	}

	out.Reset()
	if err := retractRelation(ctx, store, journalPath, id, "tester", &out); err != nil {
		t.Fatalf("retractRelation: %v", err)
	}
	if !strings.Contains(out.String(), "Removed") {
		t.Errorf("retract output missing confirmation: %q", out.String())
	}
	if _, ok := store.edges[edgeID]; ok {
		t.Errorf("edge %q should have been deleted from the store", edgeID)
	}
	if _, err := j.PendingRelation(id); err == nil {
		t.Errorf("a retracted proposal must not be pending again")
	}
}
