// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package backlogdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Backlog item states.
const (
	StateQueued = 0
	StateLeased = 1
	StateDone   = 2
)

type Options struct {
	// BusyTimeout controls how long SQLite waits on locks before failing.
	// Default: 30 seconds.
	BusyTimeout time.Duration

	// JournalMode controls the SQLite journal mode.
	// Default: "WAL".
	JournalMode string
}

type BacklogDB struct {
	sync.Mutex
	db *sql.DB
}

// NewBacklogDB opens (or creates) a SQLite backlog DB at dbPath and ensures schema exists.
// Uses modernc.org/sqlite (driver name: "sqlite").
//
// Note: This config is optimized for per-session backlogs (single writer).
func NewBacklogDB(dbPath string, opt Options) (*BacklogDB, error) {
	if opt.BusyTimeout <= 0 {
		opt.BusyTimeout = 30 * time.Second
	}
	if opt.JournalMode == "" {
		opt.JournalMode = "WAL"
	}

	// Pragmas via query string.
	// modernc.org/sqlite uses "_pragma=" syntax.
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(%s)&_pragma=foreign_keys(ON)",
		dbPath,
		int(opt.BusyTimeout.Milliseconds()),
		opt.JournalMode,
	)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// Per-session backlog: keep SQLite simple and avoid contention.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(1 * time.Hour)
	db.SetConnMaxIdleTime(10 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &BacklogDB{db: db}, nil
}

func (b *BacklogDB) Close() error {
	if b == nil || b.db == nil {
		return nil
	}

	b.Lock()
	defer b.Unlock()

	return b.db.Close()
}

func migrate(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS backlog_items (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at   INTEGER NOT NULL,
			updated_at   INTEGER NOT NULL,
			etype        TEXT    NOT NULL,
			entity_id    TEXT    NOT NULL UNIQUE,
			state        INTEGER NOT NULL, -- 0=queued,1=leased,2=done
			lease_owner  TEXT,
			lease_until  INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_backlog_etype_state_created
			ON backlog_items(etype, state, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_backlog_lease_until
			ON backlog_items(lease_until);`,
	}

	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func nowUnix() int64 { return time.Now().Unix() }

func makeInClause(ids []int64) (string, []any, error) {
	if len(ids) == 0 {
		return "", nil, errors.New("empty id list")
	}
	ph := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		ph = append(ph, "?")
		args = append(args, id)
	}
	return strings.Join(ph, ","), args, nil
}
