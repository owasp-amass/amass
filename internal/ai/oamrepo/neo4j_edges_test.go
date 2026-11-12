// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	assetdb "github.com/owasp-amass/asset-db"
	neo4jrepo "github.com/owasp-amass/asset-db/repository/neo4j"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

func TestNeo4jBoundedEdgeQuery(t *testing.T) {
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	query, params, err := neo4jBoundedEdgeQuery("42", "out", since, 5, []string{"node", "dns_record"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(n:Entity {entity_id: $eid})-[r]->(:Entity)",
		"r.updated_at >= $since",
		"type(r) IN $types",
		"ORDER BY updated DESC, rid DESC LIMIT $lim",
	} {
		if !strings.Contains(query, want) {
			t.Errorf("query %q lacks %q", query, want)
		}
	}
	if params["eid"] != "42" || params["lim"] != int64(6) {
		t.Errorf("unexpected params %#v", params)
	}

	types, _ := params["types"].([]string)
	if len(types) != 2 || types[0] != "NODE" || types[1] != "DNS_RECORD" {
		t.Errorf("labels must match upper-cased relationship types, got %#v", params["types"])
	}

	in, _, err := neo4jBoundedEdgeQuery("42", "in", time.Time{}, 1, nil)
	if err != nil || !strings.Contains(in, "<-[r]-") || strings.Contains(in, "WHERE") {
		t.Errorf("incoming query without filters: %q err=%v", in, err)
	}

	both, _, err := neo4jBoundedEdgeQuery("42", "both", time.Time{}, 1, nil)
	if err != nil || !strings.Contains(both, ")-[r]-(") {
		t.Errorf("undirected query: %q err=%v", both, err)
	}

	for name, call := range map[string]func() error{
		"no entity":     func() error { _, _, e := neo4jBoundedEdgeQuery("", "in", time.Time{}, 1, nil); return e },
		"zero limit":    func() error { _, _, e := neo4jBoundedEdgeQuery("1", "in", time.Time{}, 0, nil); return e },
		"huge limit":    func() error { _, _, e := neo4jBoundedEdgeQuery("1", "in", time.Time{}, 501, nil); return e },
		"bad direction": func() error { _, _, e := neo4jBoundedEdgeQuery("1", "sideways", time.Time{}, 1, nil); return e },
		"empty label":   func() error { _, _, e := neo4jBoundedEdgeQuery("1", "in", time.Time{}, 1, []string{""}); return e },
		"too many labels": func() error {
			_, _, e := neo4jBoundedEdgeQuery("1", "in", time.Time{}, 1, make([]string, 9))
			return e
		},
	} {
		if call() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestNeo4jDatabaseName(t *testing.T) {
	cfg := &config.Config{GraphDBs: []*config.Database{
		{System: "local", Primary: false},
		{System: "bolt", Primary: true, URL: "bolt://neo4j:secret@db:7687/assets"},
	}}
	if got := Neo4jDatabaseName(cfg); got != "assets" {
		t.Errorf("got %q, want assets", got)
	}

	cfg.GraphDBs[1].URL = "bolt://db:7687"
	if got := Neo4jDatabaseName(cfg); got != "" {
		t.Errorf("no path should select the server default, got %q", got)
	}

	cfg.GraphDBs[1].System = "postgres"
	if got := Neo4jDatabaseName(cfg); got != "" {
		t.Errorf("non-Neo4j primary must yield empty, got %q", got)
	}
	if Neo4jDatabaseName(nil) != "" {
		t.Error("nil config must yield empty")
	}
}

// TestAdapterBoundedTraversalOnNeo4j runs only when AMASS_AI_TEST_NEO4J_DSN
// names a disposable Neo4j database, as in the ai-integration CI job.
func TestAdapterBoundedTraversalOnNeo4j(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_TEST_NEO4J_DSN")
	if dsn == "" {
		t.Skip("set AMASS_AI_TEST_NEO4J_DSN to a disposable Neo4j database")
	}

	repo, err := assetdb.New(neo4jrepo.Neo4j, dsn)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repo.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	root, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: "root-" + suffix + ".example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		dest, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: name + "." + "root-" + suffix + ".example"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = repo.CreateEdge(ctx,
			&dbt.Edge{FromEntity: root, ToEntity: dest, Relation: &oamgen.SimpleRelation{Name: "node"}}); err != nil {
			t.Fatal(err)
		}
	}

	dbname := Neo4jDatabaseName(&config.Config{GraphDBs: []*config.Database{{System: "bolt", Primary: true, URL: dsn}}})
	adapter := Adapter{Repo: repo, Neo4jDatabase: dbname}
	edges, more, err := adapter.EdgesLimited(ctx, root.ID, "out", "node", time.Time{}, 1)
	if err != nil || len(edges) != 1 || !more {
		t.Fatalf("bounded page: len=%d more=%v err=%v", len(edges), more, err)
	}

	edges, more, err = adapter.EdgesLimited(ctx, root.ID, "out", "node", time.Time{}, 2)
	if err != nil || len(edges) != 2 || more {
		t.Fatalf("complete page: len=%d more=%v err=%v", len(edges), more, err)
	}
	for _, e := range edges {
		if e.FromID != root.ID || e.Label != "node" || e.Direction != "out" {
			t.Fatalf("unexpected edge %#v", e)
		}
	}

	in, _, err := adapter.EdgesLimited(ctx, edges[0].ToID, "in", "", time.Time{}, 5)
	if err != nil || len(in) != 1 || in[0].Direction != "in" {
		t.Fatalf("incoming page: %#v err=%v", in, err)
	}

	none, more, err := adapter.EdgesLimited(ctx, root.ID, "out", "dns_record", time.Time{}, 5)
	if err != nil || len(none) != 0 || more {
		t.Fatalf("label filter: len=%d more=%v err=%v", len(none), more, err)
	}
	assertAdapterPages(t, repo, adapter)
}
