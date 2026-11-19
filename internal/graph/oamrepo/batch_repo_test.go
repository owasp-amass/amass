// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	neo4jrepo "github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// onlyRepository hides asset-db's batch reads, so the adapter's fallbacks
// are compared with them.
type onlyRepository struct{ repository.Repository }

func (o onlyRepository) ReadEdgesLimited(ctx context.Context, e *dbt.Entity, dir string, since time.Time, limit int,
	labels ...string) ([]*dbt.Edge, bool, error) {
	return o.Repository.(interface {
		ReadEdgesLimited(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, bool, error)
	}).ReadEdgesLimited(ctx, e, dir, since, limit, labels...)
}

func assertBatchReads(t *testing.T, repo repository.Repository, fallback bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: "batch.example"})
	if err != nil {
		t.Fatal(err)
	}

	var ids []string
	for i := 0; i < 4; i++ {
		child, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%d.batch.example", i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: root, ToEntity: child,
			Relation: &oamgen.SimpleRelation{Name: "node"}}); err != nil {
			t.Fatal(err)
		}

		ids = append(ids, child.ID)
	}

	svc, err := repo.CreateAsset(ctx, &oamplat.Service{ID: "batch-svc", Type: "HTTP", Output: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: root, ToEntity: svc,
		Relation: &oamgen.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"}}); err != nil {
		t.Fatal(err)
	}

	batch := Adapter{Repo: repo, Stats: &ReadStats{}}
	adapters := map[string]Adapter{"batch": batch}
	if fallback {
		adapters["fallback"] = Adapter{Repo: onlyRepository{repo}}
	}

	want := append(slices.Clone(ids), svc.ID, root.ID)
	for name, a := range adapters {
		got, err := a.GetAssets(ctx, append(slices.Clone(want), "987654321"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(want) || got[svc.ID].Type != "Service" || got[ids[2]].Key != "h2.batch.example" {
			t.Fatalf("%s: got %d assets: %v", name, len(got), got)
		}

		edges, more, err := a.EdgesPerLabel(ctx, root.ID, "out", []string{"node", "port"}, time.Time{}, 3)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		labels := map[string]int{}
		for _, e := range edges {
			labels[e.Label]++
			if e.Direction != "out" || e.FromID != root.ID {
				t.Fatalf("%s: edge %+v", name, e)
			}
		}
		// The fallback's "port" read cannot filter by label (port relations
		// may be stored under their own names), so it may report more.
		if labels["node"] != 3 || labels["port"] != 1 || !slices.Contains(more, "node") ||
			(name == "batch" && !slices.Equal(more, []string{"node"})) {
			t.Fatalf("%s: labels %v more %v", name, labels, more)
		}

		edges, more, err = a.EdgesPerLabel(ctx, ids[0], "in", []string{"node"}, time.Time{}, 3)
		if err != nil || len(edges) != 1 || len(more) != 0 || edges[0].Direction != "in" {
			t.Fatalf("%s: in edges %v more %v err %v", name, edges, more, err)
		}
	}
	for name, a := range adapters {
		got, more, err := a.EdgesForAssets(ctx, []string{root.ID, ids[0], "987654321"}, "out", time.Time{}, 3)
		if err != nil || len(got[root.ID]) != 3 || !more[root.ID] || len(got[ids[0]]) != 0 || len(more) != 1 {
			t.Fatalf("%s: out edges %v more %v err %v", name, got, more, err)
		}

		in, more, err := a.EdgesForAssets(ctx, []string{ids[1], svc.ID}, "in", time.Time{}, 3)
		if err != nil || len(more) != 0 || len(in[ids[1]]) != 1 || len(in[svc.ID]) != 1 ||
			in[svc.ID][0].Label != "port" || in[svc.ID][0].Direction != "in" {
			t.Fatalf("%s: in edges %v more %v err %v", name, in, more, err)
		}
	}
	if batch.Stats.calls["GetAssets"] != 1 || batch.Stats.calls["EdgesPerLabel"] != 2 ||
		batch.Stats.calls["EdgesForAssets"] != 2 {
		t.Errorf("stats %v", batch.Stats.calls)
	}
}

func TestAdapterBatchReadsOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "batch.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repo.Close() }()
	assertBatchReads(t, repo, true)
}

// TestAdapterBatchReadsOnPostgres runs against the empty PostgreSQL
// database named by AMASS_TEST_POSTGRES_BATCH_DSN.
func TestAdapterBatchReadsOnPostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_TEST_POSTGRES_BATCH_DSN")
	if dsn == "" {
		t.Skip("AMASS_TEST_POSTGRES_BATCH_DSN is not set")
	}

	repo, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repo.Close() }()
	assertBatchReads(t, repo, true)
}

// TestAdapterBatchReadsOnNeo4j runs against the disposable Neo4j database
// named by AMASS_TEST_NEO4J_DSN.
func TestAdapterBatchReadsOnNeo4j(t *testing.T) {
	dsn := os.Getenv("AMASS_TEST_NEO4J_DSN")
	if dsn == "" {
		t.Skip("set AMASS_TEST_NEO4J_DSN to a disposable Neo4j database")
	}

	repo, err := assetdb.New(neo4jrepo.Neo4j, dsn)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repo.Close() }()
	assertBatchReads(t, repo, false)
}

var _ graph.AssetBatchReader = Adapter{}
