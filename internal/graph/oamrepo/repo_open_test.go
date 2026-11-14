// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"path/filepath"
	"testing"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

// openSQLite opens a new SQLite Asset Database for one test.
func openSQLite(t *testing.T, name string) repository.Repository {
	t.Helper()
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	return repo
}
