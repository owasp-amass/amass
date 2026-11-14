// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"os"
	"testing"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	neo4jrepo "github.com/owasp-amass/asset-db/repository/neo4j"
)

// TestLensesOnNeo4j runs the lens, review and adapter checks the SQLite
// tests run against the disposable Neo4j database named by
// AMASS_AI_TEST_NEO4J_DSN, as in the ai-integration CI job. Each check starts
// from an empty database, since several read every stored organization.
func TestLensesOnNeo4j(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_TEST_NEO4J_DSN")
	if dsn == "" {
		t.Skip("set AMASS_AI_TEST_NEO4J_DSN to a disposable Neo4j database")
	}

	repo, err := assetdb.New(neo4jrepo.Neo4j, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	for _, c := range []struct {
		name  string
		check func(*testing.T, repository.Repository)
	}{
		{"family", checkOrganizationFamily},
		{"org-group", checkCorporateGroup},
		{"services", checkServices},
		{"network", checkNetworkInfrastructure},
		{"dangling DNS", checkDanglingDNS},
		{"person-named removal", checkPersonNamedRemoval},
		{"duplicates", findGlobalSignDuplicates},
		{"identity", identityConflicts},
		{"merge", mergeAndUnmerge},
		{"service signals", checkServiceSignals},
	} {
		t.Run(c.name, func(t *testing.T) {
			emptyNeo4j(t, repo)
			c.check(t, repo)
		})
	}
}

// emptyNeo4j deletes everything in the test database.
func emptyNeo4j(t *testing.T, repo repository.Repository) {
	t.Helper()
	neo, ok := repo.(*neo4jrepo.NeoRepository)
	if !ok || neo.DB == nil {
		t.Fatalf("not a Neo4j repository: %T", repo)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := neo4jdb.ExecuteQuery(ctx, neo.DB, "MATCH (n) DETACH DELETE n", nil,
		neo4jdb.EagerResultTransformer); err != nil {
		t.Fatal(err)
	}
}
