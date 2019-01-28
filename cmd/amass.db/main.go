// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/OWASP/Amass/amass/handlers"
)

var (
	help  = flag.Bool("h", false, "Show the program usage message")
	input = flag.String("i", "", "The Amass data operations JSON file")
	user  = flag.String("u", "", "The database username")
	pass  = flag.String("p", "", "The database password")
	neo4j = flag.String("neo4j", "", "URL to the Neo4j database (i.e. localhost:7687)")
	grem  = flag.String("grem", "", "URL to a Gremlin database (i.e. localhost:8182)")
)

func main() {
	flag.Parse()

	if *help {
		fmt.Printf("Usage: %s -i infile --neo4j URL\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		return
	}

	if *input == "" {
		fmt.Println("The data operations JSON file must be provided using the '-i' flag")
		return
	}

	f, err := os.Open(*input)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	opts, err := handlers.ParseDataOpts(f)
	if err != nil {
		fmt.Println("Failed to parse the provided data operations")
		return
	}

	if *neo4j == "" {
		fmt.Println("The '-neo4j' flag must be provided with the Neo4j connection URL")
		return
	}

	var db handlers.DataHandler
	if *neo4j != "" {
		neo, err := handlers.NewNeo4j(*neo4j, *user, *pass, nil)
		if err != nil {
			fmt.Println("Failed to connect with the database")
			return
		}
		defer neo.Close()
		db = neo
	} else if *grem != "" {
		g, err := handlers.NewGremlin(*grem, *user, *pass, nil)
		if err != nil {
			fmt.Println("Failed to connect with the database")
			return
		}
		defer g.Close()
		db = g
	}

	err = handlers.DataOptsDriver(opts, db)
	if err != nil {
		fmt.Printf("Failed to populate the database: %v\n", err)
	}
}
