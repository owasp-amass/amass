// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"strings"

	"github.com/go-ini/ini"
)

// Database contains values required for connecting with graph databases.
type Database struct {
	System   string
	Primary  bool   `ini:"primary"`
	URL      string `ini:"url"`
	Username string `ini:"username"`
	Password string `ini:"password"`
	DBName   string `ini:"database"`
	Options  string `ini:"options"`
}

func (c *Config) loadDatabaseSettings(cfg *ini.File) error {
	sec, err := cfg.GetSection("graphdbs")
	if err != nil {
		return nil
	}

	if sec.HasKey("local_database") {
		if localdb, err := sec.Key("local_database").Bool(); err == nil {
			c.LocalDatabase = localdb
		}
	}

	for _, child := range sec.ChildSections() {
		db := new(Database)
		name := strings.Split(child.Name(), ".")[1]

		// Parse the Database information and assign to the Config
		if err := child.MapTo(db); err == nil {
			db.System = name
			c.GraphDBs = append(c.GraphDBs, db)
		}
	}

	return nil
}

// LocalDatabaseSettings returns the Database for the local bolt store.
func (c *Config) LocalDatabaseSettings(dbs []*Database) *Database {
	if !c.LocalDatabase {
		return nil
	}

	bolt := &Database{
		System:  "local",
		Primary: true,
		URL:     OutputDirectory(c.Dir),
		Options: "nosync=true",
	}

	for _, db := range dbs {
		if db.Primary {
			bolt.Primary = false
			break
		}
	}

	return bolt
}
