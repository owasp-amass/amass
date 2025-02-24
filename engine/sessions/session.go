// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caffix/stringset"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/pubsub"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/cache"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/yl2chen/cidranger"
)

type Session struct {
	id       uuid.UUID
	log      *slog.Logger
	ps       *pubsub.Logger
	cfg      *config.Config
	scope    *scope.Scope
	db       repository.Repository
	queue    *sessionQueue
	dsn      string
	dbtype   string
	cache    *cache.Cache
	ranger   cidranger.Ranger
	tmpdir   string
	stats    *et.SessionStats
	done     chan struct{}
	finished bool
	set      *stringset.Set
}

// CreateSession initializes a new Session object based on the provided configuration.
// The session object represents the state of an active engine enumeration.
func CreateSession(cfg *config.Config) (et.Session, error) {
	// Use default configuration if none is provided
	if cfg == nil {
		cfg = config.NewConfig()
	}
	// Create a new session object
	s := &Session{
		id:     uuid.New(),
		cfg:    cfg,
		scope:  scope.CreateFromConfigScope(cfg),
		ranger: NewAmassRanger(),
		ps:     pubsub.NewLogger(),
		stats:  new(et.SessionStats),
		done:   make(chan struct{}),
		set:    stringset.New(),
	}
	s.log = slog.New(slog.NewJSONHandler(s.ps, nil)).With("session", s.id)

	err := s.setupDB()
	if err != nil {
		return nil, err
	}

	s.tmpdir, err = s.createTemporaryDir()
	if err != nil {
		return nil, err
	}

	c, err := s.createFileRepo("cache.sqlite")
	if err != nil {
		return nil, err
	}

	s.cache, err = cache.New(c, s.db, time.Minute)
	if err != nil || s.cache == nil {
		return nil, errors.New("failed to create the session cache")
	}

	s.queue = newSessionQueue(s)
	s.log.Info("Session initialized")
	s.log.Info("Temporary directory created", slog.String("dir", s.tmpdir))
	s.log.Info("Database connection established", slog.String("dsn", s.dsn))
	return s, nil
}

func (s *Session) ID() uuid.UUID {
	return s.id
}

func (s *Session) Log() *slog.Logger {
	return s.log
}

func (s *Session) PubSub() *pubsub.Logger {
	return s.ps
}

func (s *Session) Config() *config.Config {
	return s.cfg
}

func (s *Session) Scope() *scope.Scope {
	return s.scope
}

func (s *Session) DB() repository.Repository {
	return s.db
}

func (s *Session) Cache() *cache.Cache {
	return s.cache
}

func (s *Session) Queue() et.SessionQueue {
	return s.queue
}

func (s *Session) CIDRanger() cidranger.Ranger {
	return s.ranger
}

func (s *Session) TmpDir() string {
	return s.tmpdir
}

func (s *Session) Stats() *et.SessionStats {
	return s.stats
}

func (s *Session) EventSet() *stringset.Set {
	return s.set
}

func (s *Session) Done() bool {
	return s.finished
}

func (s *Session) Kill() {
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	s.finished = true
}

func (s *Session) setupDB() error {
	if err := s.selectDBMS(); err != nil {
		return err
	}
	return nil
}

func (s *Session) selectDBMS() error {
	// If no graph databases are specified, use a default SQLite database.
	if s.cfg.GraphDBs == nil {
		s.cfg.GraphDBs = []*config.Database{
			{
				Primary: true,
				System:  "sqlite",
			},
		}
	}
	// Iterate over the GraphDBs specified in the configuration.
	// The goal is to determine the primary database's connection details.
	for _, db := range s.cfg.GraphDBs {
		if db.Primary {
			// Convert the database system name to lowercase for consistent comparison.
			db.System = strings.ToLower(db.System)
			if db.System == "postgres" {
				// Construct the connection string for a Postgres database.
				s.dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				s.dbtype = sqlrepo.Postgres
			} else if db.System == "sqlite" || db.System == "sqlite3" {
				// Define the connection path for an SQLite database.
				path := filepath.Join(config.OutputDirectory(s.cfg.Dir), "amass.sqlite")
				s.dsn = path
				s.dbtype = sqlrepo.SQLite
			} else if db.System == "neo4j" || db.System == "neo4+s" || db.System == "neo4j+sec" ||
				db.System == "bolt" || db.System == "bolt+s" || db.System == "bolt+sec" {
				s.dsn = db.URL
				s.dbtype = neo4j.Neo4j
			}
			// Break the loop once the primary database is found.
			break
		}
	}
	// Check if a valid database connection string was generated.
	if s.dsn == "" || s.dbtype == "" {
		return errors.New("no primary database specified in the configuration")
	}
	// Initialize the database store
	store, err := assetdb.New(s.dbtype, s.dsn)
	if err != nil {
		return errors.New("failed to initialize database store")
	}
	s.db = store
	return nil
}

func (s *Session) createTemporaryDir() (string, error) {
	outdir := config.OutputDirectory()
	if outdir == "" {
		return "", errors.New("failed to obtain the output directory")
	}

	dir, err := os.MkdirTemp(outdir, "session-"+s.ID().String())
	if err != nil {
		return "", errors.New("failed to create the temp dir")
	}

	return dir, nil
}

func (s *Session) createFileRepo(fname string) (repository.Repository, error) {
	c, err := assetdb.New(sqlrepo.SQLite, filepath.Join(s.TmpDir(), fname))

	if err != nil {
		return nil, fmt.Errorf("failed to create the db: %s", err.Error())
	}
	return c, nil
}

type sessionQueue struct {
	sync.Mutex
	session *Session
	q       map[string][]string
}

func newSessionQueue(s *Session) *sessionQueue {
	return &sessionQueue{
		session: s,
		q:       make(map[string][]string),
	}
}

func (sq *sessionQueue) Append(e *dbt.Entity) error {
	sq.Lock()
	defer sq.Unlock()

	if e == nil {
		return errors.New("entity is nil")
	}
	if e.Asset == nil {
		return errors.New("asset is nil")
	}

	key := string(e.Asset.AssetType())
	if key == "" {
		return errors.New("asset type is empty")
	}
	if _, found := sq.q[key]; !found {
		sq.q[key] = make([]string, 0)
	}
	if e.ID == "" {
		return errors.New("entity ID is empty")
	}

	sq.q[key] = append(sq.q[key], e.ID)
	return nil
}

func (sq *sessionQueue) Next(atype oam.AssetType, num int) ([]*dbt.Entity, error) {
	var ids []string
	key := string(atype)

	sq.Lock()
	if q, found := sq.q[key]; found {
		if len(q) > num {
			ids = q[:num]
			sq.q[key] = q[num:]
		} else {
			ids = q
			delete(sq.q, key)
		}
	}
	sq.Unlock()

	var results []*dbt.Entity
	for _, id := range ids {
		if e, err := sq.session.Cache().FindEntityById(id); err == nil {
			results = append(results, e)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("no entities found")
	}
	return results, nil
}
