// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/postgres"
)

// TestTokenAndSPFAttributeOwnershipOnPostgres runs the value signals against
// the empty PostgreSQL database named by AMASS_AI_POSTGRES_TEST_DSN.
func TestTokenAndSPFAttributeOwnershipOnPostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("AMASS_AI_POSTGRES_TEST_DSN is not set")
	}

	db, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	ents := tokenSeed(t, db)
	adapter := Adapter{Repo: db}
	ctx := context.Background()

	owner, err := adapter.GetAsset(ctx, ents["colgate"].ID)
	if err != nil {
		t.Fatal(err)
	}

	j := &ai.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	res, err := ai.AttributeOwnership(ctx, adapter, Catalog{}, owner, adapter, j, ai.AttributionPolicy{Mode: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 1 || !slices.Contains(res.Applied[0].Proposal.SignalIDs, "txt_verification_token") ||
		!slices.Contains(res.Applied[0].Proposal.SignalIDs, "email_auth_reference") {
		t.Fatalf("applied = %+v; candidates = %+v", res.Applied, res.Report.Candidates)
	}
}
