// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

func TestEdgeEndsAndFQDNScopeOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "batch.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repo.Close() }()
	ctx := context.Background()

	root, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: "scope.example"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		child, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%d.scope.example", i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: root, ToEntity: child,
			Relation: &oamgen.SimpleRelation{Name: "node"}}); err != nil {
			t.Fatal(err)
		}

		grand, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("w.h%d.scope.example", i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: child, ToEntity: grand,
			Relation: &oamgen.SimpleRelation{Name: "node"}}); err != nil {
			t.Fatal(err)
		}
	}

	edges, err := repo.OutgoingEdges(ctx, root, time.Time{}, "node")
	if err != nil {
		t.Fatal(err)
	}

	ends := EdgeEnds(ctx, repo, edges, false)
	if len(ends) != 3 {
		t.Fatalf("ends = %v", ends)
	}
	if got := EntitiesByIds(ctx, repo, []string{root.ID, "987654321"}); len(got) != 1 || got[root.ID] == nil {
		t.Fatalf("by ids = %v", got)
	}

	found, err := FindByFQDNScope(ctx, repo, root, time.Time{})
	if err != nil || len(found) != 7 {
		t.Fatalf("scope found %d, %v", len(found), err)
	}
}
