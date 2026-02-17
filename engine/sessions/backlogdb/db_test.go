// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package backlogdb

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", fmt.Sprintf("backlog-test-%d", rand.Intn(100000)))
	require.NoError(t, err, "failed to create temp dir")
	return dir
}

func openTestBacklog(t *testing.T) (*BacklogDB, string) {
	t.Helper()

	dir := makeTempDir(t)
	dbPath := filepath.Join(dir, "backlog.sqlite")

	db, err := NewBacklogDB(dbPath, Options{
		BusyTimeout: 5 * time.Second,
		JournalMode: "WAL",
	})
	require.NoError(t, err)
	require.NotNil(t, db)

	t.Cleanup(func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	})

	return db, dbPath
}

func TestBacklogDBSchema(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Validate table exists
	var tbl string
	err := db.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name='backlog_items'`,
	).Scan(&tbl)
	require.NoError(t, err)
	assert.Equal(t, "backlog_items", tbl)

	// Validate indexes exist
	indexes := map[string]bool{}
	rows, err := db.db.QueryContext(ctx, `PRAGMA index_list('backlog_items')`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	// index_list columns: seq, name, unique, origin, partial
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin string
		var partial int
		require.NoError(t, rows.Scan(&seq, &name, &unique, &origin, &partial))
		indexes[name] = true
	}
	require.NoError(t, rows.Err())

	assert.True(t, indexes["sqlite_autoindex_backlog_items_1"], "unique index for entity_id should exist")
	assert.True(t, indexes["idx_backlog_etype_state_created"], "etype/state/created index should exist")
	assert.True(t, indexes["idx_backlog_lease_until"], "lease_until index should exist")
}
