// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"embed"
	"fmt"
	"math/rand"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"github.com/owasp-amass/amass/v4/config"
	assetdb "github.com/owasp-amass/asset-db"
	pgmigrations "github.com/owasp-amass/asset-db/migrations/postgres"
	sqlitemigrations "github.com/owasp-amass/asset-db/migrations/sqlite3"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	migrate "github.com/rubenv/sql-migrate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func OpenGraphDatabase(cfg *config.Config) *assetdb.AssetDB {
	// Add the local database settings to the configuration
	cfg.GraphDBs = append(cfg.GraphDBs, cfg.LocalDatabaseSettings(cfg.GraphDBs))

	for _, db := range cfg.GraphDBs {
		if db.Primary {
			var dbase *assetdb.AssetDB

			if db.System == "local" {
				dbase = NewGraph(db.System, filepath.Join(config.OutputDirectory(cfg.Dir), "amass.sqlite"), db.Options)
			} else {
				connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				dbase = NewGraph(db.System, connStr, db.Options)
			}

			if dbase != nil {
				return dbase
			}
			break
		}
	}

	return NewGraph("memory", "", "")
}

func NewGraph(system, path string, options string) *assetdb.AssetDB {
	var dsn string
	var dbtype string

	switch system {
	case "memory":
		dbtype = sqlrepo.SQLite
		dsn = fmt.Sprintf("file:sqlite%d?mode=memory&cache=shared", rand.Int31n(100))
	case "local":
		dbtype = sqlrepo.SQLite
		dsn = path
	case "postgres":
		dbtype = sqlrepo.Postgres
		dsn = path
	default:
		return nil
	}

	store := assetdb.New(dbtype, dsn)
	if store == nil {
		return nil
	}

	var name string
	var fs embed.FS
	var database gorm.Dialector
	switch dbtype {
	case sqlrepo.SQLite:
		name = "sqlite3"
		fs = sqlitemigrations.Migrations()
		database = sqlite.Open(dsn)
	case sqlrepo.Postgres:
		name = "postgres"
		fs = pgmigrations.Migrations()
		database = postgres.Open(dsn)
	}

	sql, err := gorm.Open(database, &gorm.Config{})
	if err != nil {
		return nil
	}

	migrationsSource := migrate.EmbedFileSystemMigrationSource{
		FileSystem: fs,
		Root:       "/",
	}

	sqlDb, err := sql.DB()
	if err != nil {
		panic(err)
	}

	_, err = migrate.Exec(sqlDb, name, migrationsSource, migrate.Up)
	if err != nil {
		panic(err)
	}
	return store
}
