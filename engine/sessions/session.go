// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
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
)

type Session struct {
	id     uuid.UUID
	log    *slog.Logger
	ps     *pubsub.Logger
	cfg    *config.Config
	scope  *scope.Scope
	db     repository.Repository
	dsn    string
	dbtype string
	c      *cache.Cache
	tmpdir string
	stats  *et.SessionStats
	done   chan struct{}
	set    *stringset.Set
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
		id:    uuid.New(),
		cfg:   cfg,
		scope: scope.CreateFromConfigScope(cfg),
		ps:    pubsub.NewLogger(),
		stats: new(et.SessionStats),
		done:  make(chan struct{}),
		set:   stringset.New(),
	}
	s.log = slog.New(slog.NewJSONHandler(s.ps, nil)).With("session", s.id)

	if err := s.setupDB(); err != nil {
		return nil, err
	}

	c, dir, err := createFileCacheRepo()
	if err != nil {
		return nil, err
	}
	s.tmpdir = dir

	s.c, err = cache.New(c, s.db, time.Minute)
	if err != nil || s.c == nil {
		return nil, errors.New("failed to create the session cache")
	}
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
	return s.c
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
	select {
	case <-s.done:
		return true
	default:
	}
	return false
}

func (s *Session) Kill() {
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
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

func createFileCacheRepo() (repository.Repository, string, error) {
	dir, err := os.MkdirTemp("", fmt.Sprintf("test-%d", rand.Intn(100)))
	if err != nil {
		return nil, "", errors.New("failed to create the temp dir")
	}

	//c, err := assetdb.New(sqlrepo.SQLiteMemory, "")
	c, err := assetdb.New(sqlrepo.SQLite, filepath.Join(dir, "cache.sqlite"))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create the cache db: %s", err.Error())
	}

	return c, dir, nil
}
