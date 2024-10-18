// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// oam_assoc: Analyze collected OAM data to identify assets associated with the seed data
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
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/utils"
	"github.com/owasp-amass/amass/v4/utils/afmt"
	assetdb "github.com/owasp-amass/asset-db"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
)

const (
	timeFormat = "01/02 15:04:05 2006 MST"
	usageMsg   = "[options] [-since '" + timeFormat + "'] " + "-d domain"
)

type assocArgs struct {
	Domains *stringset.Set
	Since   string
	Options struct {
		NoColor bool
		Silent  bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
	}
}

func main() {
	var args assocArgs
	var help1, help2 bool
	assocCommand := flag.NewFlagSet("assoc", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	assocBuf := new(bytes.Buffer)
	assocCommand.SetOutput(assocBuf)

	assocCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	assocCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	assocCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	assocCommand.StringVar(&args.Since, "since", "", "Exclude all assets discovered before (format: "+timeFormat+")")
	assocCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	assocCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	assocCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	assocCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	assocCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing registered domain names")

	var usage = func() {
		afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), usageMsg)
		assocCommand.PrintDefaults()
		afmt.G.Fprintln(color.Error, assocBuf.String())
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := assocCommand.Parse(os.Args[1:]); err != nil {
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

	for _, name := range args.Domains.Slice() {
		for _, assoc := range getAssociations(name, start, db) {
			afmt.G.Fprintln(color.Output, assoc)
		}
	}
}

func getAssociations(fqdn string, since time.Time, db *assetdb.AssetDB) []string {
	if !since.IsZero() {
		since = since.UTC()
	}

	assets, err := db.FindByContent(&domain.FQDN{Name: fqdn}, since)
	if err != nil || len(assets) == 0 {
		return []string{}
	}

	set := stringset.New()
	defer set.Close()

	for _, asset := range assets {
		set.Insert(asset.ID)
	}

	var results []string
	for findings := assets; len(findings) > 0; {
		assets = findings
		findings = []*dbt.Asset{}

		for _, a := range assets {
			if rels, err := db.OutgoingRelations(a, since, "associated_with"); err == nil && len(rels) > 0 {
				for _, rel := range rels {
					asset := rel.ToAsset

					if !set.Has(asset.ID) {
						set.Insert(asset.ID)
						findings = append(findings, asset)
						results = append(results, asset.Asset.Key())
					}
				}
			}
		}
	}
	return results
}
