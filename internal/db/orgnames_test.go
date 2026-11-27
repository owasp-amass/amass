// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestNormalizeOrganizationNames(t *testing.T) {
	repo, err := sqlite3.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "orgs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()
	ctx := context.Background()

	stored := map[string]*oamorg.Organization{
		// stored by the engine under the earlier normalization
		"old": {ID: "acme corp:6f3c1c62-3f1e-4c55-9d38-0b4f6c0f8a11", Name: "acme corp"},
		// stored by the engine under the current normalization
		"current": {ID: "globex:0b8c4b6e-1a2b-4c3d-8e9f-001122334455", Name: "globex"},
		// a seed organization stored as given
		"seed": {ID: "Initech LLC", Name: "Initech LLC"},
		// renamed after it was created: no longer the engine's name
		"renamed": {ID: "umbrella:7e57d004-2b97-4e1c-8f1a-6a3e3c1d2b10", Name: "Umbrella Corporation"},
	}
	for _, o := range stored {
		if _, err := repo.CreateAsset(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	n, err := NormalizeOrganizationNames(ctx, repo)
	if err != nil || n != 1 {
		t.Fatalf("rewrote %d names, %v; want 1", n, err)
	}
	want := map[string]string{"old": "acme", "current": "globex", "seed": "Initech LLC",
		"renamed": "Umbrella Corporation"}
	for k, o := range stored {
		ents, err := repo.FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 1, dbt.ContentFilters{"unique_id": o.ID})
		if err != nil || len(ents) != 1 {
			t.Fatalf("%s: %v", k, err)
		}
		if got := ents[0].Asset.(*oamorg.Organization).Name; got != want[k] {
			t.Errorf("%s: name = %q, want %q", k, got, want[k])
		}
	}

	// a second pass has nothing to do
	if n, err := NormalizeOrganizationNames(ctx, repo); err != nil || n != 0 {
		t.Errorf("second pass rewrote %d, %v", n, err)
	}
}

func TestEngineCreated(t *testing.T) {
	for id, want := range map[string]bool{
		"acme:6f3c1c62-3f1e-4c55-9d38-0b4f6c0f8a11":     true,
		"a:b corp:6f3c1c62-3f1e-4c55-9d38-0b4f6c0f8a11": true,
		"acme":            false,
		"acme:not-a-uuid": false,
		"other:6f3c1c62-3f1e-4c55-9d38-0b4f6c0f8a11": false,
	} {
		name := "acme"
		if id == "a:b corp:6f3c1c62-3f1e-4c55-9d38-0b4f6c0f8a11" {
			name = "a:b corp"
		}
		if got := engineCreated(&oamorg.Organization{ID: id, Name: name}); got != want {
			t.Errorf("engineCreated(%q, %q) = %v, want %v", id, name, got, want)
		}
	}
}
