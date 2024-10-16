// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"
)

func TestLoadDatabaseSettings(t *testing.T) {
	// Test with no database in options
	c := NewConfig()
	c.Options = make(map[string]interface{})
	err := c.loadDatabaseSettings(c)
	if err != nil {
		t.Errorf("Got an error when no database is provided, expected nil. Error: %v", err)
	}

	// Test with invalid type in database
	c = NewConfig()
	c.Options = make(map[string]interface{})
	c.Options["database"] = 1234
	err = c.loadDatabaseSettings(c)
	if err == nil {
		t.Errorf("Expected an error when database is not a string or array of strings, got nil")
	}

	// Test with invalid URI
	c = NewConfig()
	c.Options = make(map[string]interface{})
	c.Options["database"] = "not a valid URI"
	err = c.loadDatabaseSettings(c)
	if err == nil {
		t.Errorf("Expected an error when database is not a valid URI, got nil")
	}

	// Test with valid URI without password but with database name
	c = NewConfig()
	c.Options = make(map[string]interface{})
	c.Options["database"] = "mysql://username@localhost/mydatabase"
	err = c.loadDatabaseSettings(c)
	if err != nil {
		t.Errorf("Got an error when valid database is provided, expected nil. Error: %v", err)
	}

	if len(c.GraphDBs) != 1 {
		t.Errorf("Expected GraphDBs to have one element, got %v", len(c.GraphDBs))
	} else {
		db := c.GraphDBs[0]
		if db.Username != "username" || db.System != "mysql" || db.URL != "mysql://username@localhost/mydatabase" {
			t.Errorf("Database struct does not match expected values after loading valid database without password and path")
		}
	}

	// Test with valid URI with password and path
	c = NewConfig()
	c.Options = make(map[string]interface{})
	c.Options["database"] = "postgres://username:password@localhost:5432/database?sslmode=disable"
	err = c.loadDatabaseSettings(c)
	if err != nil {
		t.Errorf("Got an error when valid database is provided, expected nil. Error: %v", err)
	}

	if len(c.GraphDBs) != 1 {
		t.Errorf("Expected GraphDBs to have one element, got %v", len(c.GraphDBs))
	} else {
		db := c.GraphDBs[0]
		if db.Username != "username" || db.Password != "password" || db.System != "postgres" ||
			db.URL != "postgres://username:password@localhost:5432/database?sslmode=disable" || db.DBName != "database" || db.Options != "sslmode=disable" {
			t.Errorf("Database struct does not match expected values after loading valid database with password and path")
		}
	}
}

func TestLocalDatabaseSettings(t *testing.T) {
	c := NewConfig()
	c.Dir = "/tmp" // Set the directory to a known value for testing.

	// Scenario 1: Test with no primary database in the slice.
	dbs := []*Database{
		{System: "remote", Primary: false},
		{System: "another_remote", Primary: false},
	}
	localDB := c.LocalDatabaseSettings(dbs)
	if localDB.Primary != true {
		t.Errorf("Expected localDB.Primary to be true when no primary database is in the slice, got false")
	}
	if localDB.URL != OutputDirectory("/tmp") {
		t.Errorf("Expected localDB.URL to be %s, got %s", OutputDirectory("/tmp"), localDB.URL)
	}

	// Scenario 2: Test with a primary database in the slice.
	dbs = []*Database{
		{System: "remote", Primary: false},
		{System: "another_remote", Primary: true},
	}
	localDB = c.LocalDatabaseSettings(dbs)
	if localDB.Primary != false {
		t.Errorf("Expected localDB.Primary to be false when a primary database is in the slice, got true")
	}
}
func TestLoadDatabaseEnvSettings(t *testing.T) {
	c := NewConfig()

	// Scenario 1: Test with valid environment variables
	os.Setenv(amassUser, "the_inceptions")
	os.Setenv(amassPass, "was_here")
	os.Setenv(assetDB, "192.168.24.14")
	os.Setenv(assetPort, "5432")
	os.Setenv(assetDBName, "inceptionsdb")

	err := c.LoadDatabaseEnvSettings()
	if err != nil {
		t.Errorf("Got an error when valid environment variables are set, expected nil. Error: %v", err)
	}

	expectedDBURI := "postgres://the_inceptions:was_here@192.168.24.14:5432/inceptionsdb"
	if c.GraphDBs[0].URL != expectedDBURI {
		t.Errorf("Expected DB URI to be %s, got %s", expectedDBURI, c.GraphDBs[0].URL)
	}

	// Clean up environment variables
	os.Unsetenv(amassUser)
	os.Unsetenv(amassPass)
	os.Unsetenv(assetDB)
	os.Unsetenv(assetPort)
	os.Unsetenv(assetDBName)

	// // Scenario 2: Test with just the user environment variables
	os.Setenv(amassUser, "the_inceptions")
	err = c.LoadDatabaseEnvSettings()
	if err != nil {
		t.Errorf("Got an error when only the user environment variable is set, expected nil. Error: %v", err)
	}

	expectedDBURI = "postgres://the_inceptions@localhost:5432/assetdb"
	if c.GraphDBs[1].URL != expectedDBURI {
		t.Errorf("Expected DB URI to be %s, got %s", expectedDBURI, c.GraphDBs[0].URL)
	}

	// Clean up environment variables
	os.Unsetenv(amassUser)

	// // Scenario 3: Test with no environment variables
	err = c.LoadDatabaseEnvSettings()
	if err != nil {
		t.Errorf("Expected no error when no environment variables are set, got an error %v", err)
	}
}
