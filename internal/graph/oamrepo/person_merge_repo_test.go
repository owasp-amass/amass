// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oampeople "github.com/owasp-amass/open-asset-model/people"
)

func TestMergePersonsMovesEdgesAndFillsFieldsOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "person_merge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx := context.Background()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	// The survivor lacks a middle name; the duplicate carries it. The duplicate
	// also holds an email identifier the merge must move onto the survivor.
	surv := f.asset(&oampeople.Person{ID: "John Smith", FullName: "John Smith", FirstName: "John", FamilyName: "Smith"})
	dup := f.asset(&oampeople.Person{ID: "John A Smith", FullName: "John A Smith", FirstName: "John",
		MiddleName: "A", FamilyName: "Smith"})
	ident := f.asset(&oamgen.Identifier{UniqueID: "email:john@example.com", ID: "john@example.com", Type: "email"})
	f.edge(dup, ident, "id", "amass-ai")

	a := Adapter{Repo: repo}
	rec, err := a.MergePersons(ctx, surv.ID, dup.ID, 75)
	if err != nil {
		t.Fatal(err)
	}

	// The duplicate is gone.
	if _, err := repo.FindEntityById(ctx, dup.ID); err == nil {
		t.Error("the duplicate person was not deleted")
	}
	// Its identifier edge moved onto the survivor.
	edges, err := a.Edges(ctx, surv.ID, "out", "id", time.Time{})
	if err != nil || len(edges) == 0 || edges[0].ToID != ident.ID {
		t.Errorf("the identifier edge did not move to the survivor: %+v, %v", edges, err)
	}
	// The survivor gained the duplicate's middle name.
	got, err := a.GetAsset(ctx, surv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m := graph.ContentString(got, "middle_name"); m != "A" {
		t.Errorf("survivor middle name = %q, want A (filled from the duplicate)", m)
	}
	if !slices.Contains(rec.FilledFields, "middle_name") {
		t.Errorf("merge record did not note the filled middle name: %+v", rec.FilledFields)
	}
}
