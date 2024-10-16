// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/cache"
	"github.com/owasp-amass/amass/v4/engine/pubsub"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v4/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository"
	migrate "github.com/rubenv/sql-migrate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Session struct {
	id     uuid.UUID
	log    *slog.Logger
	ps     *pubsub.Logger
	cfg    *config.Config
	scope  *scope.Scope
	db     *assetdb.AssetDB
	dsn    string
	dbtype repository.DBType
	c      cache.Cache
	stats  *et.SessionStats
	done   chan struct{}
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
		c:     cache.NewOAMCache(nil),
		stats: new(et.SessionStats),
		done:  make(chan struct{}),
	}
	s.log = slog.New(slog.NewJSONHandler(s.ps, nil)).With("session", s.id)

	if err := s.setupDB(); err != nil {
		return nil, err
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

func (s *Session) DB() *assetdb.AssetDB {
	return s.db
}

func (s *Session) Cache() cache.Cache {
	return s.c
}

func (s *Session) Stats() *et.SessionStats {
	return s.stats
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
	if err := s.migrations(); err != nil {
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
				s.dbtype = repository.Postgres
			} else if db.System == "sqlite" || db.System == "sqlite3" {
				// Define the connection path for an SQLite database.
				path := filepath.Join(config.OutputDirectory(s.cfg.Dir), "amass.sqlite")
				s.dsn = path
				s.dbtype = repository.SQLite
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
	store := assetdb.New(s.dbtype, s.dsn)
	if store == nil {
		return errors.New("failed to initialize database store")
	}
	s.db = store
	return nil
}

func (s *Session) migrations() error {
	var name string
	var fs embed.FS
	var database gorm.Dialector

	switch s.dbtype {
	case repository.SQLite:
		name = "sqlite3"
		fs = sqlitemigrations.Migrations()
		database = sqlite.Open(s.dsn)
	case repository.Postgres:
		name = "postgres"
		fs = pgmigrations.Migrations()
		database = postgres.Open(s.dsn)
	default:
		return fmt.Errorf("unsupported database type: %s", s.dbtype)
	}
	// Initialize the GORM database connection
	sql, err := gorm.Open(database, &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to open database: %s", err)
	}
	// Set up migrations
	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}
	// Extract the raw SQL database instance
	sqlDb, err := sql.DB()
	if err != nil {
		return fmt.Errorf("failed to extract raw SQL DB from GORM: %s", err)
	}
	// Run migrations
	_, err = migrate.Exec(sqlDb, name, migrationsSource, migrate.Up)
	if err != nil {
		return fmt.Errorf("failed to execute migrations: %s", err)
	}
	return nil
}
