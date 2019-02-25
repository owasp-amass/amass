// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"os"
	"path"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/fatih/color"
)

var (
	// Colors used to ease the reading of program output
	y      = color.New(color.FgHiYellow)
	g      = color.New(color.FgHiGreen)
	r      = color.New(color.FgHiRed)
	b      = color.New(color.FgHiBlue)
	fgR    = color.New(color.FgRed)
	fgY    = color.New(color.FgYellow)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	// Command-line switches and provided parameters
	help  = flag.Bool("h", false, "Show the program usage message")
	input = flag.String("i", "", "The Amass data operations JSON file")
	user  = flag.String("u", "", "The database username")
	pass  = flag.String("p", "", "The database password")
	neo4j = flag.String("neo4j", "", "URL to the Neo4j database (i.e. localhost:7687)")
	grem  = flag.String("grem", "", "URL to a Gremlin database (i.e. localhost:8182)")
)

func main() {
	defaultBuf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(defaultBuf)
	flag.Usage = func() {
		amass.PrintBanner()
		g.Fprintf(color.Error, "Usage: %s [--neo4j URL] [--grem URL] -i infile\n\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Fprintln(color.Error, defaultBuf.String())
	}
	flag.Parse()

	if *help || len(os.Args) == 1 {
		flag.Usage()
		return
	}

	if *input == "" {
		r.Fprintln(color.Error, "The data operations JSON file must be provided using the '-i' flag")
		os.Exit(1)
	}

	f, err := os.Open(*input)
	if err != nil {
		r.Fprintf(color.Error, "Failed to open the input file: %v\n", err)
		os.Exit(1)
	}

	opts, err := handlers.ParseDataOpts(f)
	if err != nil {
		r.Fprintln(color.Error, "Failed to parse the provided data operations")
		os.Exit(1)
	}

	if *neo4j == "" && *grem == "" {
		r.Fprintf(color.Error, "The '-neo4j' or '-grem' flag must be provided with the connection URL")
		os.Exit(1)
	}

	var db handlers.DataHandler
	if *neo4j != "" {
		neo, err := handlers.NewNeo4j(*neo4j, *user, *pass, nil)
		if err != nil {
			r.Fprintf(color.Error, "Failed to connect with the database")
			os.Exit(1)
		}
		defer neo.Close()
		db = neo
	} else if *grem != "" {
		g := handlers.NewGremlin(*grem, *user, *pass, nil)
		if g == nil {
			r.Fprintf(color.Error, "Failed to connect with the database")
			os.Exit(1)
		}
		defer g.Close()
		db = g
	}

	err = handlers.DataOptsDriver(opts, db)
	if err != nil {
		r.Fprintf(color.Error, "Failed to populate the database: %v\n", err)
		os.Exit(1)
	}
}
