// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// The duplicate search lists every organization with no start time, which
// the repositories refuse unless the adapter supplies one.
func TestFindDuplicateOrganizationsOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "duplicates.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	findGlobalSignDuplicates(t, repo)
}

// TestFindDuplicateOrganizationsOnPostgres runs the same search against
// the empty PostgreSQL database named by AMASS_AI_POSTGRES_DUPLICATES_DSN.
func TestFindDuplicateOrganizationsOnPostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_POSTGRES_DUPLICATES_DSN")
	if dsn == "" {
		t.Skip("AMASS_AI_POSTGRES_DUPLICATES_DSN is not set")
	}

	repo, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	findGlobalSignDuplicates(t, repo)
}

func findGlobalSignDuplicates(t *testing.T, repo repository.Repository) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	lei, err := repo.CreateAsset(ctx, &oamgen.Identifier{UniqueID: "lei:875500H0WKURA9XATD59",
		ID: "875500H0WKURA9XATD59", Type: oamgen.LEICode})
	if err != nil {
		t.Fatal(err)
	}

	var ids []string
	for _, uid := range []string{"globalsign:1", "globalsign:2"} {
		o, err := repo.CreateAsset(ctx, &oamorg.Organization{ID: uid, Name: "globalsign", LegalName: "globalsign",
			Jurisdiction: "BE", RegistrationID: "0459134256"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: o, ToEntity: lei,
			Relation: &oamgen.SimpleRelation{Name: "id"}}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, o.ID)
	}

	r, err := ai.FindDuplicateOrganizations(ctx, Adapter{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if r.Organizations != 2 || len(r.Candidates) != 1 {
		t.Fatalf("got %d organizations and %d candidates, want 2 and 1", r.Organizations, len(r.Candidates))
	}

	c := r.Candidates[0]
	if c.Decision != ai.GapPropose {
		t.Fatalf("decision %s, want propose: %+v", c.Decision, c.Signals)
	}
	if got := []string{c.Survivor.ID, c.Duplicate.ID}; !(got[0] == ids[0] && got[1] == ids[1]) &&
		!(got[0] == ids[1] && got[1] == ids[0]) {
		t.Fatalf("pair %v, want %v", got, ids)
	}
}
