// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

/*
func TestCreateSession(t *testing.T) {
	// create a new configuration object
	cfg := config.NewConfig()

	// test the function with a nil configuration object
	if ses, err := CreateSession(nil); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
		t.Error("Session is nil")
	}
	// test the function with a valid configuration object
	if ses, err := CreateSession(cfg); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
		t.Error("Session is nil")
	}
	// test the function with an invalid configuration object
	cfg.GraphDBs = []*config.Database{}
	if ses, err := CreateSession(cfg); err == nil {
		t.Error("Expected error creating new session")
	} else if ses != nil {
		t.Error("Session should be nil")
	}

	user := "postgres"
	if u, ok := os.LookupEnv("POSTGRES_USER"); ok {
		user = u
	}

	password := "postgres"
	if p, ok := os.LookupEnv("POSTGRES_PASSWORD"); ok {
		password = p
	}

	pgdbname := "postgres"
	if pdb, ok := os.LookupEnv("POSTGRES_DB"); ok {
		pgdbname = pdb
	}
	// test the function with a valid configuration object and Postgres database
	cfg.GraphDBs = []*config.Database{
		{
			Primary:  true,
			System:   "postgres",
			Host:     "localhost",
			Port:     "5432",
			Username: user,
			Password: password,
			DBName:   pgdbname,
		},
	}
	if ses, err := CreateSession(cfg); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
		t.Error("Session is nil")
	}
	if repository.DBType(cfg.GraphDBs[0].System) != repository.Postgres {
		t.Error("Session database type is incorrect")
	}
	// test the function with a valid configuration object and SQLite database
	cfg.GraphDBs = []*config.Database{
		{
			Primary: true,
			System:  "sqlite",
		},
	}
	if ses, err := CreateSession(cfg); err != nil {
		t.Errorf("Error creating new session: %v", err)
	} else if ses == nil {
		t.Error("Session is nil")
	}
	if repository.DBType(cfg.GraphDBs[0].System) != repository.SQLite {
		t.Error("Session database type is incorrect")
	}
}
*/
