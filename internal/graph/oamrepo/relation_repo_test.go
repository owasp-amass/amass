// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// These exercise the relation framework's write path against a real SQLite
// database through the production applier (the asset-db repository) and the
// graph adapter, rather than the in-memory fakes the review package uses.

func newRelationRepo(t *testing.T) (repository.Repository, Adapter, context.Context) {
	t.Helper()
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "relation.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo, Adapter{Repo: repo}, context.Background()
}

func seedOrg(t *testing.T, ctx context.Context, repo repository.Repository, id, name string) string {
	t.Helper()
	ent, err := repo.CreateAsset(ctx, &oamorg.Organization{ID: id, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return ent.ID
}

func hasOrgUnitEdge(t *testing.T, ctx context.Context, a Adapter, fromID, toID string) bool {
	t.Helper()
	edges, err := a.Edges(ctx, fromID, "out", "org_unit", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edges {
		if e.ToID == toID {
			return true
		}
	}
	return false
}

func TestApplyRetractRelationSQLite(t *testing.T) {
	repo, a, ctx := newRelationRepo(t)

	parent := seedOrg(t, ctx, repo, "sys-uuid", "State University of New York")
	unit := seedOrg(t, ctx, repo, "poly-uuid", "SUNY Polytechnic Institute")

	j := &review.Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	p := review.RelationProposal{
		ID: review.RelationProposalID("org_unit", parent, "org_unit", unit), Kind: "org_unit",
		FromID: parent, From: "State University of New York",
		Label: "org_unit", ToID: unit, To: "SUNY Polytechnic Institute",
		Confidence: 70, Status: review.ProposalPending,
	}
	if _, err := j.SubmitRelations([]review.RelationProposal{p}); err != nil {
		t.Fatal(err)
	}

	edgeID, err := review.ApplyRelation(ctx, repo, j, p, "jeff")
	if err != nil || edgeID == "" {
		t.Fatalf("apply: edge %q err %v", edgeID, err)
	}
	if !hasOrgUnitEdge(t, ctx, a, parent, unit) {
		t.Fatal("org_unit edge was not created in the database")
	}

	if err := review.RetractRelation(ctx, repo, j, p.ID, "jeff"); err != nil {
		t.Fatal(err)
	}
	if hasOrgUnitEdge(t, ctx, a, parent, unit) {
		t.Error("org_unit edge was not removed after retract")
	}
}

func TestRecheckRelationSQLite(t *testing.T) {
	repo, a, ctx := newRelationRepo(t)

	parent := seedOrg(t, ctx, repo, "sys-uuid", "State University of New York")
	unit := seedOrg(t, ctx, repo, "poly-uuid", "SUNY Polytechnic Institute")

	j := &review.Journal{Path: filepath.Join(t.TempDir(), "j.jsonl")}
	// The witness points at a relationship that does not exist, so a re-check
	// finds the story no longer holds.
	p := review.RelationProposal{
		ID: review.RelationProposalID("org_unit", parent, "org_unit", unit), Kind: "org_unit",
		FromID: parent, From: "State University of New York",
		Label: "org_unit", ToID: unit, To: "SUNY Polytechnic Institute",
		Confidence: 70, Status: review.ProposalPending,
		Witness: []graph.WitnessEdge{{FromID: "ghost", Label: "street_address", ToID: "nowhere"}},
	}
	if _, err := j.SubmitRelations([]review.RelationProposal{p}); err != nil {
		t.Fatal(err)
	}

	// Applied automatically (not by a person), so a re-check may retract it.
	if _, err := review.ApplyRelation(ctx, repo, j, p, review.AutomaticReviewer); err != nil {
		t.Fatal(err)
	}
	if !hasOrgUnitEdge(t, ctx, a, parent, unit) {
		t.Fatal("org_unit edge was not created")
	}

	res, err := review.RecheckRelations(ctx, a, repo, j, "org_unit")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Retracted) != 1 {
		t.Fatalf("re-check should retract the AI-applied edge whose witness is gone: %+v", res)
	}
	if hasOrgUnitEdge(t, ctx, a, parent, unit) {
		t.Error("re-check did not delete the retracted edge")
	}
}
