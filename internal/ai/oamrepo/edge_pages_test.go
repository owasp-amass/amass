// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// assertAdapterPages stores seven node edges from one FQDN and reads them
// back through Adapter.EdgesPage two at a time.
func assertAdapterPages(t *testing.T, repo repository.Repository, adapter Adapter) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	root, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: "pages-" + suffix + ".example"})
	if err != nil {
		t.Fatal(err)
	}

	stored := map[string]bool{}
	for i := 0; i < 7; i++ {
		dest, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%d.pages-%s.example", i, suffix)})
		if err != nil {
			t.Fatal(err)
		}

		e, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: root, ToEntity: dest,
			Relation: &oamgen.SimpleRelation{Name: "node"}})
		if err != nil {
			t.Fatal(err)
		}
		stored[e.ID] = true
	}

	read := map[string]bool{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("paging did not end")
		}

		edges, next, err := adapter.EdgesPage(ctx, root.ID, "out", "node", time.Time{}, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(edges) > 2 {
			t.Fatalf("page of %d edges, limit 2", len(edges))
		}
		for _, e := range edges {
			if read[e.ID] || !stored[e.ID] || e.Label != "node" || e.Direction != "out" || e.FromID != root.ID {
				t.Fatalf("unexpected or repeated edge %#v", e)
			}
			read[e.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(read) != len(stored) {
		t.Errorf("paged %d of %d edges", len(read), len(stored))
	}

	none, next, err := adapter.EdgesPage(ctx, root.ID, "out", "dns_record", time.Time{}, "", 5)
	if err != nil || len(none) != 0 || next != "" {
		t.Errorf("label filter: len=%d next=%q err=%v", len(none), next, err)
	}
	if _, _, err := adapter.EdgesPage(ctx, root.ID, "out", "node", time.Time{}, "not a cursor", 5); err == nil {
		t.Error("a malformed cursor was accepted")
	}
}

func TestAdapterEdgesPageOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "pages.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	assertAdapterPages(t, repo, Adapter{Repo: repo})
}

// TestAdapterEdgesPageOnPostgres runs against the empty PostgreSQL database
// named by AMASS_AI_POSTGRES_PAGES_DSN.
func TestAdapterEdgesPageOnPostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_POSTGRES_PAGES_DSN")
	if dsn == "" {
		t.Skip("AMASS_AI_POSTGRES_PAGES_DSN is not set")
	}

	repo, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	assertAdapterPages(t, repo, Adapter{Repo: repo})
}

func TestNeo4jEdgePageQuery(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	query, params, err := neo4jEdgeQuery("42", "out", time.Time{},
		&dbt.EdgeCursor{EdgeID: "4:abc:7", SortKey: at.Format(time.RFC3339Nano)}, 5, []string{"node"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query,
		"(r.updated_at < $cursor_at OR (r.updated_at = $cursor_at AND elementId(r) < $cursor_id))") ||
		!strings.Contains(query, "ORDER BY updated DESC, rid DESC LIMIT $lim") {
		t.Errorf("query lacks the keyset condition or order: %q", query)
	}
	if params["cursor_id"] != "4:abc:7" {
		t.Errorf("cursor_id = %#v", params["cursor_id"])
	}

	for name, after := range map[string]*dbt.EdgeCursor{
		"bad time":   {EdgeID: "4:abc:7", SortKey: "yesterday"},
		"missing id": {SortKey: at.Format(time.RFC3339Nano)},
	} {
		if _, _, err := neo4jEdgeQuery("42", "out", time.Time{}, after, 5, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
