// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"testing"

	"github.com/go-ini/ini"
)

func TestLoadDatabaseSettings(t *testing.T) {
	c := NewConfig()

	cfg, _ := ini.LoadSources(
		ini.LoadOptions{
			Insensitive:  true,
			AllowShadows: true,
		},
		[]byte(`
		[graphdbs]
		local_database = true ; Set this to false to disable use of the local database.

		[graphdbs.postgres]
		primary = false ; Specify which graph database is the primary db, or the local database will be selected.
		url = "postgres://username:password@host:9999/database-name?sslmode=disable"
		options="connect_timeout=10"
		
		# MqSQL database and credentials URL format:
		[graphdbs.mysql]
		url = username:password@tcp(host:3306)/database-name?timeout=10s
		`),
	)

	if err := c.loadDatabaseSettings(cfg); err != nil {
		t.Errorf("Load failed")
	}

	sec, err := cfg.GetSection("graphdbs")
	if err != nil {
		t.Errorf("Get section failed: %v", err)
	}

	if !sec.HasKey("local_database") {
		t.Errorf("Failed to load local_database setting")
	}
}

func TestLocalDatabaseSettings(t *testing.T) {
	c := NewConfig()
	db := new(Database)
	var dbs = make([]*Database, 0)
	dbs = append(dbs, db)
	if loaded := c.LocalDatabaseSettings(dbs); loaded == nil {
		t.Errorf("LocalDatabaseSettings failed")
	}
}
