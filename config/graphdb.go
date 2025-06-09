// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Database contains values required for connecting with graph database.
type Database struct {
	System   string `json:"system,omitempty"`   // Database system type (Postgres, MySQL, etc.)
	Primary  bool   `json:"primary,omitempty"`  // Whether this database is the primary store
	URL      string `json:"url,omitempty"`      // Full URI to the database
	Username string `json:"username,omitempty"` // Username for authentication
	Password string `json:"password,omitempty"` // Password for authentication
	Host     string `json:"host,omitempty"`     // Host of the database
	Port     string `json:"port,omitempty"`     // Port of the database
	DBName   string `json:"db_name,omitempty"`  // Name of the database
	Options  string `json:"options,omitempty"`  // Extra options used while connecting to the database
}

const (
	amassUser   = "AMASS_DB_USER"
	amassPass   = "AMASS_DB_PASSWORD"
	assetDB     = "AMASS_DB_HOST"
	assetPort   = "AMASS_DB_PORT"
	assetDBName = "AMASS_DB_NAME"
)

func (c *Config) loadDatabaseSettings(cfg *Config) error {
	if c.Options == nil {
		return fmt.Errorf("config options are not initialized")
	}

	dbURIInterface, ok := c.Options["database"]
	if !ok {
		if err := c.LoadDatabaseEnvSettings(); err != nil {
			return nil
		}
	}

	dbURI, ok := dbURIInterface.(string)
	if !ok {
		return fmt.Errorf("expected 'database' to be a string, got %T", dbURIInterface)
	}

	if _, err := url.Parse(dbURI); err == nil {
		if err := c.loadDatabase(dbURI); err != nil {
			return err
		}
	}
	return nil
}

// LoadDatabaseEnvSettings initializes the DB structure with the Environment variables.
func (c *Config) LoadDatabaseEnvSettings() error {
	dbURI := ""
	db := &Database{
		Primary: true,
		System:  "postgres",
	}

	var u string
	if uenv, set := os.LookupEnv(amassUser); set {
		u = uenv
	} else {
		return fmt.Errorf("environment variable %s is not set", amassUser)
	}
	db.Username = u
	h := "localhost"
	if dbEnv, set := os.LookupEnv(assetDB); set {
		h = dbEnv
	}
	db.Host = h
	port := "5432"
	if pEnv, set := os.LookupEnv(assetPort); set {
		port = pEnv
	}
	db.Port = port
	n := "assetdb"
	if nEnv, set := os.LookupEnv(assetDBName); set {
		n = nEnv
	}
	db.DBName = n
	if p, set := os.LookupEnv(amassPass); set {
		db.Password = p
		dbURI = "postgres://" + u + ":" + p + "@" + h + ":" + port + "/" + n
	} else {
		dbURI = "postgres://" + u + "@" + h + ":" + port + "/" + n
	}
	db.URL = dbURI
	if c.GraphDBs == nil {
		c.GraphDBs = make([]*Database, 0)
	}
	c.GraphDBs = append(c.GraphDBs, db)
	return nil
}

func (c *Config) loadDatabase(dbURI string) error {
	u, err := url.Parse(dbURI)
	if err != nil {
		return err
	}
	// Check for valid scheme (database type)
	if u.Scheme == "" {
		return fmt.Errorf("missing scheme in database URI")
	}
	// Check for non-empty username
	if u.User == nil || u.User.Username() == "" {
		return fmt.Errorf("missing username in database URI")
	}
	// Check for reachable hostname
	if u.Hostname() == "" {
		return fmt.Errorf("missing hostname in database URI")
	}

	dbName := ""
	// Only get the database name if it's not empty or a single slash
	if u.Path != "" && u.Path != "/" {
		dbName = strings.TrimPrefix(u.Path, "/")
	}

	db := &Database{
		Primary:  true, // Set as primary, because it wouldn't be there otherwise.
		URL:      dbURI,
		System:   u.Scheme,
		Username: u.User.Username(),
		DBName:   dbName,
		Host:     u.Hostname(), // Hostname without port
		Port:     u.Port(),     // Get port
	}

	password, isSet := u.User.Password()
	if isSet {
		db.Password = password
	}

	if u.RawQuery != "" {
		queryParams, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return fmt.Errorf("unable to parse database URI query parameters: %v", err)
		}
		db.Options = queryParams.Encode() // Encode url.Values to a string
	}

	if c.GraphDBs == nil {
		c.GraphDBs = make([]*Database, 0)
	}
	c.GraphDBs = append(c.GraphDBs, db)

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
		if db != nil && db.Primary {
			bolt.Primary = false
			break
		}
	}

	return bolt
}
