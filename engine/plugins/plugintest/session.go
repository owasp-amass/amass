// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package plugintest gives engine plugin tests a session backed by a real
// Asset Database (SQLite in a temporary directory), so plugin code that
// reads and writes the database is tested against actual storage.
package plugintest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
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
	id      uuid.UUID
	start   time.Time
	ctx     context.Context
	cfg     *config.Config
	db      repository.Repository
	log     *slog.Logger
	stats   *et.SessionStats
	scope   et.Scope
	http    *et.SessionHTTPClients
	ranger  cidranger.Ranger
	backlog *Backlog
	ps      *pubsub.Logger
	webOnce sync.Once
	web     *Web
	dnsOnce sync.Once
	dns     *DNS

	// nameKinds decides uncertain names (SetNameKinds)
	nameKinds et.NameKindDecider
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
	var s *Session
	t.Cleanup(func() {
		cancel()
		if s != nil {
			s.ps.Close()
		}
		_ = db.Close()
	})

	// The output directory is the test's, so a review journal the plugins
	// write stays out of the user's own.
	cfg := config.NewConfig()
	cfg.Dir = t.TempDir()

	client := &http.Client{Timeout: 10 * time.Second}
	s = &Session{id: uuid.New(), start: time.Now(), ctx: ctx, cfg: cfg, db: db,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), stats: &et.SessionStats{},
		http:   &et.SessionHTTPClients{General: client, Probe: client, Crawl: client, Bulk: client},
		ranger: cidranger.NewPCTrieRanger(), backlog: &Backlog{}, ps: pubsub.NewLogger()}
	s.scope = scope.New(s)

	return s
}

func (s *Session) ID() uuid.UUID { return s.id }

func (s *Session) StartTime() time.Time { return s.start }

func (s *Session) Ctx() context.Context { return s.ctx }

func (s *Session) Log() *slog.Logger { return s.log }

func (s *Session) Config() *config.Config { return s.cfg }

func (s *Session) DB() repository.Repository { return s.db }

func (s *Session) Stats() *et.SessionStats { return s.stats }

func (s *Session) Done() bool { return s.ctx.Err() != nil }

// Scope is the session's scope, empty until the test adds to it.
func (s *Session) Scope() et.Scope { return s.scope }

// NameKinds is the decider SetNameKinds gave the session, or nil.
func (s *Session) NameKinds() et.NameKindDecider { return s.nameKinds }

// SetNameKinds gives the session a decider of uncertain names.
func (s *Session) SetNameKinds(d et.NameKindDecider) { s.nameKinds = d }

// NetSem never makes a test wait.
func (s *Session) NetSem() et.SessionSemaphone { return noSem{} }

// CIDRanger holds the netblocks plugin code adds.
func (s *Session) CIDRanger() cidranger.Ranger { return s.ranger }

// Clients are plain HTTP clients, for tests that serve their own pages.
func (s *Session) Clients() *et.SessionHTTPClients { return s.http }

// Web routes every request the session's HTTP clients send to handlers the
// test registers, in process, so plugin code that fetches from fixed URLs runs
// against canned answers. A request no handler matches gets 404 and is still
// recorded. The first call installs it on the session's clients.
func (s *Session) Web() *Web {
	s.webOnce.Do(func() {
		s.web = &Web{mux: http.NewServeMux()}
		client := &http.Client{Timeout: 10 * time.Second, Transport: s.web}
		s.http.General, s.http.Probe, s.http.Crawl, s.http.Bulk = client, client, client, client
	})
	return s.web
}

// Web is the fake web of a test session (Session.Web).
type Web struct {
	mu       sync.Mutex
	mux      *http.ServeMux
	requests []string
}

// Handle registers a handler for a pattern that names the host, such as
// "GET api.example.com/v1/search" or "data.example.org/" (net/http.ServeMux
// patterns).
func (w *Web) Handle(pattern string, h http.HandlerFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.mux.HandleFunc(pattern, h)
}

// Reply registers a handler that answers a pattern with a status and body.
func (w *Web) Reply(pattern string, status int, body string) {
	w.Handle(pattern, func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(status)
		_, _ = io.WriteString(rw, body)
	})
}

// Requests returns the requests sent so far, each "METHOD host/path?query".
func (w *Web) Requests() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]string(nil), w.requests...)
}

// RoundTrip answers a request from the registered handlers.
func (w *Web) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if r.Host == "" {
		r.Host = r.URL.Host
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}

	w.mu.Lock()
	line := r.Method + " " + r.URL.Host + r.URL.Path
	if r.URL.RawQuery != "" {
		line += "?" + r.URL.RawQuery
	}
	w.requests = append(w.requests, line)
	w.mu.Unlock()

	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// PubSub returns the session's log stream.
func (s *Session) PubSub() *pubsub.Logger { return s.ps }

// Backlog returns the session's backlog, which keeps what is enqueued.
func (s *Session) Backlog() et.Backlog { return s.backlog }

// Enqueued returns the entities enqueued on the session's backlog so far.
func (s *Session) Enqueued() []*dbt.Entity { return s.backlog.Entities() }

type noSem struct{}

// Backlog is the part of et.Backlog that plugin code under test uses: it
// keeps the enqueued entities. The other methods panic when called.
type Backlog struct {
	et.Backlog
	mu       sync.Mutex
	entities []*dbt.Entity
}

// Enqueue keeps the entity.
func (b *Backlog) Enqueue(e *dbt.Entity) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entities = append(b.entities, e)
	return nil
}

// Has reports whether the entity was enqueued.
func (b *Backlog) Has(e *dbt.Entity) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, x := range b.entities {
		if x.ID == e.ID {
			return true
		}
	}
	return false
}

// Entities returns the entities enqueued so far.
func (b *Backlog) Entities() []*dbt.Entity {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]*dbt.Entity(nil), b.entities...)
}

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

// APIKeys configures the data source with the API keys, as an operator's
// datasources file would, so plugin code that reads its keys finds them.
func (s *Session) APIKeys(source string, keys ...string) {
	creds := map[string]*config.Credentials{}
	for i, k := range keys {
		name := fmt.Sprintf("account%d", i)
		creds[name] = &config.Credentials{Name: name, Apikey: k}
	}

	if s.cfg.DataSrcConfigs == nil {
		s.cfg.DataSrcConfigs = &config.DataSourceConfig{}
	}
	s.cfg.DataSrcConfigs.Datasources = append(s.cfg.DataSrcConfigs.Datasources,
		&config.DataSource{Name: source, Creds: creds})
}
