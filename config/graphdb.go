// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

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
	bolt := &Database{
		System:  "local",
		Primary: true,
		URL:     OutputDirectory(c.Dir),
	}

	for _, db := range dbs {
		if db.Primary {
			bolt.Primary = false
			break
		}
	}

	return bolt
}
