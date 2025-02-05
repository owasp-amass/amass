// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"path/filepath"

	"github.com/owasp-amass/amass/v4/config"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
)

func OpenGraphDatabase(cfg *config.Config) repository.Repository {
	// Add the local database settings to the configuration
	cfg.GraphDBs = append(cfg.GraphDBs, cfg.LocalDatabaseSettings(cfg.GraphDBs))

	for _, db := range cfg.GraphDBs {
		if db.Primary {
			var dbase repository.Repository

			if db.System == "local" {
				dbase = NewGraph(db.System, filepath.Join(config.OutputDirectory(cfg.Dir), "amass.sqlite"), db.Options)
			} else if db.System == "postgres" {
				connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				dbase = NewGraph(db.System, connStr, db.Options)
			} else {
				dbase = NewGraph(db.System, db.URL, db.Options)
			}

			if dbase != nil {
				return dbase
			}
			break
		}
	}

	return NewGraph("memory", "", "")
}

func NewGraph(system, path string, options string) repository.Repository {
	var dsn string
	var dbtype string

	switch system {
	case "memory":
		dbtype = sqlrepo.SQLiteMemory
	case "local":
		dbtype = sqlrepo.SQLite
		dsn = path
	case "postgres":
		dbtype = sqlrepo.Postgres
		dsn = path
	case "bolt":
		dbtype = neo4j.Neo4j
		dsn = path
	default:
		return nil
	}

	if store, err := assetdb.New(dbtype, dsn); err == nil {
		return store
	}
	return nil
}
