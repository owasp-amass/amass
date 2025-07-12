// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

const (
	TimeFormat  string = "01/02 15:04:05 2006 MST"
	UsageMsg    string = "-d3|-dot|-gexf [options] -d domain"
	Description string = "Analyze OAM data to generate graph visualizations"
)

type Args struct {
	Help    bool
	Domains *stringset.Set
	Since   string
	Options struct {
		D3      bool
		DOT     bool
		GEXF    bool
		NoColor bool
		Silent  bool
	}
	Filepaths struct {
		ConfigFile    string
		Directory     string
		Domains       string
		Output        string
		AllFilePrefix string
	}
}

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("viz", errorHandling)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	fs.StringVar(&args.Since, "since", "", "Include only assets validated after (format: "+TimeFormat+")")
	fs.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	fs.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	fs.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing registered domain names")
	fs.StringVar(&args.Filepaths.Output, "o", "", "Path to the directory for output files being generated")
	fs.StringVar(&args.Filepaths.AllFilePrefix, "oA", "", "Path prefix used for naming all output files")
	fs.BoolVar(&args.Options.D3, "d3", false, "Generate the D3 v4 force simulation HTML file")
	fs.BoolVar(&args.Options.DOT, "dot", false, "Generate the DOT output file")
	fs.BoolVar(&args.Options.GEXF, "gexf", false, "Generate the Gephi Graph Exchange XML Format (GEXF) file")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	return fs
}

func CLIWorkflow(cmdName string, clArgs []string) {
	var args Args
	args.Domains = stringset.New()
	defer args.Domains.Close()

	fs := NewFlagset(&args, flag.ContinueOnError)
	vizBuf := new(bytes.Buffer)
	fs.SetOutput(vizBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", cmdName, UsageMsg)

		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, vizBuf.String())
			return
		}

		_, _ = afmt.G.Fprintln(color.Error, "Use the -h or --help flag to see the flags and default values")
		_, _ = afmt.G.Fprintf(color.Error, "\nThe Amass Discord server can be found here: %s\n\n", afmt.DiscordInvitation)
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := fs.Parse(clArgs); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if args.Help {
		usage()
		return
	}
	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = io.Discard
		color.Error = io.Discard
	}
	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		args.Domains.InsertMany(list...)
	}
	if args.Domains.Len() == 0 {
		_, _ = afmt.R.Fprintln(color.Error, "No root domain names were provided")
		os.Exit(1)
	}
	// Make sure at least one graph file format has been identified on the command-line
	if !args.Options.D3 && !args.Options.DOT && !args.Options.GEXF {
		_, _ = afmt.R.Fprintln(color.Error, "At least one file format must be selected")
		os.Exit(1)
	}

	var err error
	var start time.Time
	if args.Since != "" {
		start, err = time.Parse(TimeFormat, args.Since)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "%s is not in the correct format: %s\n", args.Since, TimeFormat)
			os.Exit(1)
		}
	}

	cfg := config.NewConfig()
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = cfg.Dir
		}
		if args.Domains.Len() == 0 {
			args.Domains.InsertMany(cfg.Domains()...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}
	// Connect with the graph database containing the enumeration data
	db := tools.OpenGraphDatabase(cfg)
	if db == nil {
		_, _ = afmt.R.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	// Obtain the visualization nodes & edges from the graph
	nodes, edges := VizData(args.Domains.Slice(), start, db)
	// Get the directory to save the files into
	dir := args.Filepaths.Directory
	if pwd, err := os.Getwd(); err == nil {
		dir = pwd
	}

	// Set output file prefix, use 'amass' if '-oA' flag is not specified
	prefix := args.Filepaths.AllFilePrefix
	if prefix == "" {
		prefix = "amass"
	}

	if args.Filepaths.Output != "" {
		if finfo, err := os.Stat(args.Filepaths.Output); os.IsNotExist(err) || !finfo.IsDir() {
			_, _ = afmt.R.Fprintln(color.Error, "The output location does not exist or is not a directory")
			os.Exit(1)
		}
		dir = args.Filepaths.Output
	}
	if args.Options.D3 {
		path := filepath.Join(dir, prefix+".html")
		err = writeGraphOutputFile("d3", path, nodes, edges)
	}
	if args.Options.DOT {
		path := filepath.Join(dir, prefix+".dot")
		err = writeGraphOutputFile("dot", path, nodes, edges)
	}
	if args.Options.GEXF {
		path := filepath.Join(dir, prefix+".gexf")
		err = writeGraphOutputFile("gexf", path, nodes, edges)
	}
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to write the output file: %v\n", err)
		os.Exit(1)
	}
}

func writeGraphOutputFile(t string, path string, nodes []Node, edges []Edge) error {
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
		err = WriteD3Data(f, nodes, edges)
	case "dot":
		err = WriteDOTData(f, nodes, edges)
	case "gexf":
		err = WriteGEXFData(f, nodes, edges)
	}
	return err
}
