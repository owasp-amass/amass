// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/internal/afmt"
	"github.com/owasp-amass/amass/v4/internal/tools"
	"github.com/owasp-amass/asset-db/triples"
)

const (
	UsageMsg    = "[options] [-tf path] [-t1 triple] ... [-t10 triple]"
	Description = "Query the OAM along the walk defined by the triples"
)

type Args struct {
	Help    bool
	Triples []string // The triples to use for the association walk
	Options struct {
		NoColor bool
		Silent  bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		TripleFile string
	}
}

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("assoc", errorHandling)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.StringVar(&args.Triples[0], "t1", "", "1st triple to use for the association walk")
	fs.StringVar(&args.Triples[1], "t2", "", "2nd triple to use for the association walk")
	fs.StringVar(&args.Triples[2], "t3", "", "3rd triple to use for the association walk")
	fs.StringVar(&args.Triples[3], "t4", "", "4th triple to use for the association walk")
	fs.StringVar(&args.Triples[4], "t5", "", "5th triple to use for the association walk")
	fs.StringVar(&args.Triples[5], "t6", "", "6th triple to use for the association walk")
	fs.StringVar(&args.Triples[6], "t7", "", "7th triple to use for the association walk")
	fs.StringVar(&args.Triples[7], "t8", "", "8th triple to use for the association walk")
	fs.StringVar(&args.Triples[8], "t9", "", "9th triple to use for the association walk")
	fs.StringVar(&args.Triples[9], "t10", "", "10th triple to use for the association walk")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	fs.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	fs.StringVar(&args.Filepaths.TripleFile, "tf", "", "Path to a file containing a triples list")
	return fs
}

func CLIWorkflow(cmdName string, clArgs []string) {
	var args Args
	args.Triples = make([]string, 10)

	fs := NewFlagset(&args, flag.ContinueOnError)
	assocBuf := new(bytes.Buffer)
	fs.SetOutput(assocBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", cmdName, UsageMsg)

		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, assocBuf.String())
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
	if args.Filepaths.TripleFile != "" {
		list, err := config.GetListFromFile(args.Filepaths.TripleFile)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to parse the triple file: %v\n", err)
			os.Exit(1)
		}
		if len(list) > 10 {
			list = list[:10]
		}
		for i, l := range list {
			if l == "" || args.Triples[i] != "" {
				continue
			}
			args.Triples[i] = l
		}
	}
	if args.Triples[0] == "" {
		_, _ = afmt.R.Fprintln(color.Error, "No triples were provided for the association walk")
		os.Exit(1)
	}

	cfg := config.NewConfig()
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = cfg.Dir
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

	var tris []*triples.Triple
	for _, tstr := range args.Triples {
		if tstr == "" {
			break
		}

		triple, err := triples.ParseTriple(tstr)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to parse the triple '%s': %v\n", tstr, err)
			os.Exit(1)
		}
		tris = append(tris, triple)
	}
	if len(tris) == 0 {
		_, _ = afmt.R.Fprintln(color.Error, "No valid triples were provided for the association walk")
		os.Exit(1)
	}

	results, err := triples.Extract(db, tris)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to extract associations: %v\n", err)
		os.Exit(1)
	}

	// Marshal with indentation (e.g., 2 spaces)
	prettyJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Error marshaling JSON: %v", err)
		os.Exit(1)
	}

	_, _ = afmt.G.Fprintln(color.Output, string(prettyJSON))
}
