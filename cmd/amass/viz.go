// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/OWASP/Amass/v3/viz"
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
	//vizCommand.BoolVar(&args.Options.DOT, "dot", false, "Generate the DOT output file")
	vizCommand.BoolVar(&args.Options.GEXF, "gexf", false, "Generate the Gephi Graph Exchange XML Format (GEXF) file")
	vizCommand.BoolVar(&args.Options.Graphistry, "graphistry", false, "Generate the Graphistry JSON file")
	vizCommand.BoolVar(&args.Options.Maltego, "maltego", false, "Generate the Maltego csv file")

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

	if args.Filepaths.Output == "" {
		dir, err := os.Getwd()
		if err != nil {
			r.Fprintln(color.Error, "Failed to identify the output location")
			os.Exit(1)
		}
		args.Filepaths.Output = dir
	}
	if finfo, err := os.Stat(args.Filepaths.Output); os.IsNotExist(err) || !finfo.IsDir() {
		r.Fprintln(color.Error, "The output location does not exist or is not a directory")
		os.Exit(1)
	}

	var uuid string
	var db *graph.Graph
	rand.Seed(time.Now().UTC().UnixNano())

	cfg := new(config.Config)
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = cfg.Dir
		}
		if len(args.Domains) == 0 {
			args.Domains.InsertMany(cfg.Domains()...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	db = openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	defer db.Close()

	if args.Enum > 0 {
		uuid = enumIndexToID(args.Enum, args.Domains.Slice(), db)
	} else {
		// Get the UUID for the most recent enumeration
		uuid = mostRecentEnumID(args.Domains.Slice(), db)
	}

	if uuid == "" {
		r.Fprintln(color.Error, "No enumeration found within the graph database")
		os.Exit(1)
	}

	nodes, edges := db.VizData(uuid)
	if args.Options.D3 {
		dir := filepath.Join(args.Filepaths.Output, "amass_d3.html")
		writeD3File(dir, nodes, edges)
	}
	if args.Options.DOT {
		dir := filepath.Join(args.Filepaths.Output, "amass.dot")
		writeDOTData(dir, nodes, edges)
	}
	if args.Options.GEXF {
		dir := filepath.Join(args.Filepaths.Output, "amass.gexf")
		writeGEXFFile(dir, nodes, edges)
	}
	if args.Options.Graphistry {
		dir := filepath.Join(args.Filepaths.Output, "amass_graphistry.json")
		writeGraphistryFile(dir, nodes, edges)
	}
	if args.Options.Maltego {
		dir := filepath.Join(args.Filepaths.Output, "amass_maltego.csv")
		writeMaltegoFile(dir, nodes, edges)
	}
}

func writeMaltegoFile(path string, nodes []viz.Node, edges []viz.Edge) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteMaltegoData(f, nodes, edges)
	f.Sync()
}

func writeGraphistryFile(path string, nodes []viz.Node, edges []viz.Edge) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteGraphistryData(f, nodes, edges)
	f.Sync()
}

func writeGEXFFile(path string, nodes []viz.Node, edges []viz.Edge) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteGEXFData(f, nodes, edges)
	f.Sync()
}

func writeD3File(path string, nodes []viz.Node, edges []viz.Edge) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteD3Data(f, nodes, edges)
	f.Sync()
}

func writeDOTData(path string, nodes []viz.Node, edges []viz.Edge) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteDOTData(f, nodes, edges)
	f.Sync()
}
