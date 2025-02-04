// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// oam_viz: Analyze collected OAM data to generate files renderable as graph visualizations
//
//	+----------------------------------------------------------------------------+
//	| ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  OWASP Amass  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ |
//	+----------------------------------------------------------------------------+
//	|      .+++:.            :                             .+++.                 |
//	|    +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+   |
//	|   &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&   |
//	|  +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8         |
//	|  8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:       |
//	|  WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:     |
//	|  #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8    |
//	|  o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.  |
//	|   WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o  |
//	|   :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+  |
//	|    :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&   |
//	|      +o&&&&+.                                                    +oooo.    |
//	+----------------------------------------------------------------------------+
package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/utils"
	"github.com/owasp-amass/amass/v4/utils/afmt"
	"github.com/owasp-amass/amass/v4/utils/viz"
)

const (
	timeFormat = "01/02 15:04:05 2006 MST"
	usageMsg   = "-d3|-dot|-gexf [options] -d domain"
)

type vizArgs struct {
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

func main() {
	var args vizArgs
	var help1, help2 bool
	vizCommand := flag.NewFlagSet("viz", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	vizBuf := new(bytes.Buffer)
	vizCommand.SetOutput(vizBuf)

	vizCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	vizCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	vizCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	vizCommand.StringVar(&args.Since, "since", "", "Include only assets validated after (format: "+timeFormat+")")
	vizCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	vizCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	vizCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing registered domain names")
	vizCommand.StringVar(&args.Filepaths.Output, "o", "", "Path to the directory for output files being generated")
	vizCommand.StringVar(&args.Filepaths.AllFilePrefix, "oA", "", "Path prefix used for naming all output files")
	vizCommand.BoolVar(&args.Options.D3, "d3", false, "Generate the D3 v4 force simulation HTML file")
	vizCommand.BoolVar(&args.Options.DOT, "dot", false, "Generate the DOT output file")
	vizCommand.BoolVar(&args.Options.GEXF, "gexf", false, "Generate the Gephi Graph Exchange XML Format (GEXF) file")
	vizCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	vizCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")

	var usage = func() {
		afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), usageMsg)
		vizCommand.PrintDefaults()
		afmt.G.Fprintln(color.Error, vizBuf.String())
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := vizCommand.Parse(os.Args[1:]); err != nil {
		afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
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
			afmt.R.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		args.Domains.InsertMany(list...)
	}
	if args.Domains.Len() == 0 {
		afmt.R.Fprintln(color.Error, "No root domain names were provided")
		os.Exit(1)
	}
	// Make sure at least one graph file format has been identified on the command-line
	if !args.Options.D3 && !args.Options.DOT && !args.Options.GEXF {
		afmt.R.Fprintln(color.Error, "At least one file format must be selected")
		os.Exit(1)
	}

	var err error
	var start time.Time
	if args.Since != "" {
		start, err = time.Parse(timeFormat, args.Since)
		if err != nil {
			afmt.R.Fprintf(color.Error, "%s is not in the correct format: %s\n", args.Since, timeFormat)
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
		afmt.R.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}
	// Connect with the graph database containing the enumeration data
	db := utils.OpenGraphDatabase(cfg)
	if db == nil {
		afmt.R.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	// Obtain the visualization nodes & edges from the graph
	nodes, edges := viz.VizData(args.Domains.Slice(), start, db)
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
			afmt.R.Fprintln(color.Error, "The output location does not exist or is not a directory")
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
		afmt.R.Fprintf(color.Error, "Failed to write the output file: %v\n", err)
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
	}
	return err
}
