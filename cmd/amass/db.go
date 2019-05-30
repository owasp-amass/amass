// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

const (
	dbUsageMsg = "db [options]"
)

type dbArgs struct {
	Domains utils.ParseStrings
	Options struct {
		ListEnumerations bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		Input      string
	}
}

func runDBCommand(clArgs []string) {
	var args dbArgs
	var help1, help2 bool
	dbCommand := flag.NewFlagSet("db", flag.ExitOnError)

	dbBuf := new(bytes.Buffer)
	dbCommand.SetOutput(dbBuf)

	dbCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	dbCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	dbCommand.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	dbCommand.BoolVar(&args.Options.ListEnumerations, "list", false, "Show the enumerations that include identified domains")
	dbCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	dbCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	dbCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	dbCommand.StringVar(&args.Filepaths.Input, "i", "", "Import an Amass data operations JSON file to the graph database")

	if len(clArgs) < 1 {
		commandUsage(dbUsageMsg, dbCommand, dbBuf)
		return
	}

	if err := dbCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(dbUsageMsg, dbCommand, dbBuf)
		return
	}

	config := new(core.Config)
	// Check if a configuration file was provided, and if so, load the settings
	if acquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, config) {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = config.Dir
		}
	}

	db := openGraphDatabase(args.Filepaths.Directory, config)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	defer db.Close()

	// Input of data operations from a JSON file to the database
	if args.Filepaths.Input != "" {
		if err := inputDataOperations(db, &args); err != nil {
			r.Fprintf(color.Error, "Input data operations: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if args.Options.ListEnumerations {
		listEnumerations(args.Domains, db)
		return
	}
}

func openGraphDatabase(dir string, config *core.Config) handlers.DataHandler {
	var db handlers.DataHandler
	// Attempt to connect to an Amass graph database
	/*if args.Options.Neo4j {
		neo, err := handlers.NewNeo4j(args.URL, args.User, args.Password, nil)
		if err != nil {
			db = neo
		}
	} else */
	if config.GremlinURL != "" {
		if g := handlers.NewGremlin(config.GremlinURL, config.GremlinUser, config.GremlinPass, nil); g != nil {
			db = g
		}
	} else {
		if d := outputDirectory(dir); d != "" {
			// Check that the graph database directory exists
			if finfo, err := os.Stat(d); !os.IsNotExist(err) && finfo.IsDir() {
				if graph := handlers.NewGraph(d); graph != nil {
					db = graph
				}
			}
		}
	}
	return db
}

func listEnumerations(domains []string, db handlers.DataHandler) {
	var enums []string
	// Obtain the enumerations that include the provided domain
	for _, e := range db.EnumerationList() {
		if len(domains) == 0 {
			enums = append(enums, e)
		} else {
			for _, domain := range domains {
				if enumContainsDomain(e, domain, db) {
					enums = append(enums, e)
					break
				}
			}
		}
	}

	enums, earliest, latest := orderedEnumsAndDateRanges(enums, db)
	// Check if the user has requested the list of enumerations
	for i := range enums {
		g.Printf("%d) %s -> %s\n", i+1, earliest[i].Format(timeFormat), latest[i].Format(timeFormat))
	}
}

func inputDataOperations(db handlers.DataHandler, args *dbArgs) error {
	f, err := os.Open(args.Filepaths.Input)
	if err != nil {
		return fmt.Errorf("Failed to open the input file: %v", err)
	}

	opts, err := handlers.ParseDataOpts(f)
	if err != nil {
		return errors.New("Failed to parse the provided data operations")
	}

	err = handlers.DataOptsDriver(opts, db)
	if err != nil {
		return fmt.Errorf("Failed to populate the database: %v", err)
	}
	return nil
}
