// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/viz"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
)

const (
	vizUsageMsg = "viz -d3|-dot||-gexf|-graphistry|-maltego [options]"
)

type vizArgs struct {
	Domains stringset.Set
	Enum    int
	Options struct {
		D3         bool
		DOT        bool
		GEXF       bool
		Graphistry bool
		Maltego    bool
		NoColor    bool
		Silent     bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		Input      string
		Output     string
	}
}

func runVizCommand(clArgs []string) {
	var args vizArgs
	var help1, help2 bool
	vizCommand := flag.NewFlagSet("viz", flag.ContinueOnError)

	args.Domains = stringset.New()

	vizBuf := new(bytes.Buffer)
	vizCommand.SetOutput(vizBuf)

	vizCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	vizCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	vizCommand.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	vizCommand.IntVar(&args.Enum, "enum", 0, "Identify an enumeration via an index from the listing")
	vizCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	vizCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	vizCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	vizCommand.StringVar(&args.Filepaths.Input, "i", "", "The Amass data operations JSON file")
	vizCommand.StringVar(&args.Filepaths.Output, "o", "", "Path to the directory for output files being generated")
	vizCommand.BoolVar(&args.Options.D3, "d3", false, "Generate the D3 v4 force simulation HTML file")
	vizCommand.BoolVar(&args.Options.DOT, "dot", false, "Generate the DOT output file")
	vizCommand.BoolVar(&args.Options.GEXF, "gexf", false, "Generate the Gephi Graph Exchange XML Format (GEXF) file")
	vizCommand.BoolVar(&args.Options.Graphistry, "graphistry", false, "Generate the Graphistry JSON file")
	vizCommand.BoolVar(&args.Options.Maltego, "maltego", false, "Generate the Maltego csv file")
	vizCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	vizCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")

	if len(clArgs) < 1 {
		commandUsage(vizUsageMsg, vizCommand, vizBuf)
		return
	}

	if err := vizCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(vizUsageMsg, vizCommand, vizBuf)
		return
	}

	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = ioutil.Discard
		color.Error = ioutil.Discard
	}

	// Make sure at least one graph file format has been identified on the command-line
	if !args.Options.D3 && !args.Options.DOT &&
		!args.Options.GEXF && !args.Options.Graphistry && !args.Options.Maltego {
		r.Fprintln(color.Error, "At least one file format must be selected")
		os.Exit(1)
	}

	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			return
		}
		args.Domains.InsertMany(list...)
	}

	rand.Seed(time.Now().UTC().UnixNano())

	cfg := new(config.Config)
	cfg.LocalDatabase = true
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = config.OutputDirectory(cfg.Dir)
		}
		if len(args.Domains) == 0 {
			args.Domains.InsertMany(cfg.Domains()...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	db := openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	defer db.Close()

	// Create the in-memory graph database
	memDB, err := memGraphForScope(args.Domains.Slice(), db)
	if err != nil {
		r.Fprintln(color.Error, err.Error())
		os.Exit(1)
	}

	// Get all the UUIDs for events that have information in scope
	uuids := eventUUIDs(args.Domains.Slice(), memDB)
	if len(uuids) == 0 {
		r.Fprintln(color.Error, "Failed to find the domains of interest in the database")
		os.Exit(1)
	}

	// Put the events in chronological order
	uuids, _, _ = orderedEvents(uuids, memDB)
	if len(uuids) == 0 {
		r.Fprintln(color.Error, "Failed to sort the events")
		os.Exit(1)
	}

	// Select the enumeration that the user specified
	if args.Enum > 0 && len(uuids) > args.Enum {
		uuids = []string{uuids[args.Enum]}
	}

	// Need to check if all the network infrastructure information is available
	fgY.Fprintln(color.Error, "Could take a moment while acquiring AS network information")
	// Migrate the changes back to the persistent db
	if healASInfo(uuids, memDB) {
		_ = memDB.MigrateEvents(db, uuids...)
	}

	// Obtain the visualization nodes & edges from the graph
	nodes, edges := memDB.VizData(uuids)

	// Get the directory to save the files into
	dir := args.Filepaths.Directory
	if args.Filepaths.Output != "" {
		if finfo, err := os.Stat(args.Filepaths.Output); os.IsNotExist(err) || !finfo.IsDir() {
			r.Fprintln(color.Error, "The output location does not exist or is not a directory")
			os.Exit(1)
		}

		dir = args.Filepaths.Output
	}

	if args.Options.D3 {
		path := filepath.Join(dir, "amass_d3.html")
		err = writeGraphOutputFile("d3", path, nodes, edges)
	}
	if args.Options.DOT {
		path := filepath.Join(dir, "amass.dot")
		err = writeGraphOutputFile("dot", path, nodes, edges)
	}
	if args.Options.GEXF {
		path := filepath.Join(dir, "amass.gexf")
		err = writeGraphOutputFile("gexf", path, nodes, edges)
	}
	if args.Options.Graphistry {
		path := filepath.Join(dir, "amass_graphistry.json")
		err = writeGraphOutputFile("graphistry", path, nodes, edges)
	}
	if args.Options.Maltego {
		path := filepath.Join(dir, "amass_maltego.csv")
		err = writeGraphOutputFile("maltego", path, nodes, edges)
	}

	if err != nil {
		r.Fprintf(color.Error, "Failed to write the output file: %v\n", err)
		os.Exit(1)
	}
}

func writeGraphOutputFile(t string, path string, nodes []viz.Node, edges []viz.Edge) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Sync()
		_ = f.Close()
	}()

	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)

	switch t {
	case "d3":
		err = viz.WriteD3Data(f, nodes, edges)
	case "dot":
		err = viz.WriteDOTData(f, nodes, edges)
	case "gexf":
		err = viz.WriteGEXFData(f, nodes, edges)
	case "graphistry":
		err = viz.WriteGraphistryData(f, nodes, edges)
	case "maltego":
		viz.WriteMaltegoData(f, nodes, edges)
	}

	return err
}
