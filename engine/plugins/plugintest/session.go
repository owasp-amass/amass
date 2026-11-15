// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package plugintest gives engine plugin tests a session backed by a real
// Asset Database (SQLite in a temporary directory), so plugin code that
// reads and writes the database is tested against actual storage.
package plugintest

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/yl2chen/cidranger"
)

// Session is the part of et.Session that plugin code under test uses; the
// other methods panic when called.
type Session struct {
	et.Session
	id     uuid.UUID
	ctx    context.Context
	cfg    *config.Config
	db     repository.Repository
	log    *slog.Logger
	stats  *et.SessionStats
	scope  et.Scope
	http   *et.SessionHTTPClients
	ranger cidranger.Ranger
}

// NewSession returns a session over a new SQLite database, closed when the
// test ends.
func NewSession(t testing.TB) *Session {
	t.Helper()

	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "plugintest.db"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = db.Close()
	})

	client := &http.Client{Timeout: 10 * time.Second}
	s := &Session{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), stats: &et.SessionStats{},
		http:   &et.SessionHTTPClients{General: client, Probe: client, Crawl: client},
		ranger: cidranger.NewPCTrieRanger()}
	s.scope = scope.New(s)

	return s
}

func (s *Session) ID() uuid.UUID { return s.id }

func (s *Session) Ctx() context.Context { return s.ctx }

func (s *Session) Log() *slog.Logger { return s.log }

func (s *Session) Config() *config.Config { return s.cfg }

func (s *Session) DB() repository.Repository { return s.db }

func (s *Session) Stats() *et.SessionStats { return s.stats }

func (s *Session) Done() bool { return s.ctx.Err() != nil }

// Scope is the session's scope, empty until the test adds to it.
func (s *Session) Scope() et.Scope { return s.scope }

// NetSem never makes a test wait.
func (s *Session) NetSem() et.SessionSemaphone { return noSem{} }

// CIDRanger holds the netblocks plugin code adds.
func (s *Session) CIDRanger() cidranger.Ranger { return s.ranger }

// Clients are plain HTTP clients, for tests that serve their own pages.
func (s *Session) Clients() *et.SessionHTTPClients { return s.http }

type noSem struct{}

func (noSem) Acquire() {}

func (noSem) Release() {}

// Dispatcher keeps the events plugin code dispatches.
type Dispatcher struct {
	mu     sync.Mutex
	events []*et.Event
}

// DispatchEvent keeps the event.
func (d *Dispatcher) DispatchEvent(e *et.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.events = append(d.events, e)
	return nil
}

// Shutdown does nothing.
func (d *Dispatcher) Shutdown() {}

// Events returns the events dispatched so far.
func (d *Dispatcher) Events() []*et.Event {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]*et.Event(nil), d.events...)
}

// Names returns the names of the events dispatched so far.
func (d *Dispatcher) Names() []string {
	var out []string
	for _, e := range d.Events() {
		out = append(out, e.Name)
	}

	return out
}

// Asset stores a in the session's database and returns its entity.
func (s *Session) Asset(t testing.TB, a oam.Asset) *dbt.Entity { return Asset(t, s.db, a) }

// Asset stores a and returns its entity, failing the test on an error.
func Asset(t testing.TB, db repository.Repository, a oam.Asset) *dbt.Entity {
	t.Helper()

	e, err := db.CreateAsset(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}

	return e
}

// Edge stores a relation between two entities, failing the test on an error.
func (s *Session) Edge(t testing.TB, from *dbt.Entity, rel oam.Relation, to *dbt.Entity) *dbt.Edge {
	t.Helper()

	e, err := s.db.CreateEdge(context.Background(), &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
	if err != nil {
		t.Fatal(err)
	}

	return e
}

// TTL lets every asset type transform to every other with the given time
// to live in minutes, as an enumeration's configuration would, so the
// plugin code under test finds its TTLs.
func (s *Session) TTL(minutes int) {
	s.cfg.Transformations = map[string]*config.Transformation{}
	for _, t := range oam.AssetList {
		from := strings.ToLower(string(t))
		s.cfg.Transformations[from+"->all"] = &config.Transformation{From: from, To: "all", TTL: minutes,
			Confidence: 100}
	}
}

// WrapDB replaces the session's repository with wrap(repository), such as a
// wrapper that counts calls.
func (s *Session) WrapDB(wrap func(repository.Repository) repository.Repository) { s.db = wrap(s.db) }
