// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// The group lens reads stored subsidiary relationships, as the GLEIF plugin
// writes them (parent --subsidiary--> child), through the adapter.
func TestCorporateGroupOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "group.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	org := func(id, name, jur string) *dbt.Entity {
		e, err := repo.CreateAsset(ctx, &oamorg.Organization{ID: id, Name: name, Jurisdiction: jur})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	sub := func(parent, child *dbt.Entity) {
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: parent, ToEntity: child,
			Relation: &oamgen.SimpleRelation{Name: "subsidiary"}}); err != nil {
			t.Fatal(err)
		}
	}

	top := org("group-top", "Example Group Holdings", "LU")
	mid := org("group-mid", "Example Operations AB", "SE")
	leaf := org("group-leaf", "Example USA Inc.", "US-DE")
	sib := org("group-sib", "Example Limited", "GB")
	sub(top, mid)
	sub(mid, leaf)
	sub(mid, sib)

	adapter := Adapter{Repo: repo}
	subject, err := adapter.GetAsset(ctx, leaf.ID)
	if err != nil {
		t.Fatal(err)
	}

	r, err := ai.FindCorporateGroup(ctx, adapter, subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Tops) != 1 || r.Tops[0].ID != top.ID || len(r.Members) != 4 || r.Truncated {
		t.Fatalf("tops %+v, %d members, truncated %v (%s)\n%s", r.Tops, len(r.Members), r.Truncated, r.Reason,
			ai.FormatGroupReport(r))
	}
	for _, m := range r.Members {
		if m.Organization.ID == sib.ID && (m.Depth != 2 || m.ParentID != mid.ID || m.Jurisdiction != "GB") {
			t.Errorf("sibling member = %+v", m)
		}
	}
}
