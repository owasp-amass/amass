// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

func TestDBStatsCountsCallsByCaller(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repo.Close() }()

	if wrapped, stats := withDBStats(repo); stats != nil || wrapped != repo {
		t.Fatal("the repository was wrapped without AMASS_DB_STATS")
	}

	t.Setenv(DBStatsEnv, "1")
	wrapped, stats := withDBStats(repo)
	if stats == nil {
		t.Fatal("the repository was not wrapped")
	}
	if _, ok := wrapped.(sqlReads); !ok {
		t.Fatal("the wrapped repository hides the optional reads")
	}

	ctx := context.Background()
	ent, err := wrapped.CreateAsset(ctx, &oamdns.FQDN{Name: "stats.example"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := wrapped.FindEntityById(ctx, ent.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := wrapped.(sqlReads).ReadEdgesLimited(ctx, ent, "out", time.Time{}, 5); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	stats.log(slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()
	for _, want := range []string{"calls=5", "TestDBStatsCountsCallsByCaller FindEntityById\" calls=3",
		"ReadEdgesLimited"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}
