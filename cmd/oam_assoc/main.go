// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/utils"
	"github.com/owasp-amass/amass/v4/utils/afmt"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
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
	var help1, help2, verbose bool
	assocCommand := flag.NewFlagSet("assoc", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	assocBuf := new(bytes.Buffer)
	assocCommand.SetOutput(assocBuf)

	assocCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	assocCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	assocCommand.BoolVar(&verbose, "v", false, "Show additional information about the associated assets")
	assocCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	assocCommand.StringVar(&args.Since, "since", "", "Exclude all assets discovered before (format: "+timeFormat+")")
	assocCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	assocCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	assocCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	assocCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	assocCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing registered domain names")

	var usage = func() {
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), usageMsg)
		assocCommand.PrintDefaults()
		_, _ = afmt.G.Fprintln(color.Error, assocBuf.String())
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := assocCommand.Parse(os.Args[1:]); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
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
			_, _ = afmt.R.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		args.Domains.InsertMany(list...)
	}
	if args.Domains.Len() == 0 {
		_, _ = afmt.R.Fprintln(color.Error, "No root domain names were provided")
		os.Exit(1)
	}

	var err error
	var start time.Time
	if args.Since != "" {
		start, err = time.Parse(timeFormat, args.Since)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "%s is not in the correct format: %s\n", args.Since, timeFormat)
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
	db := utils.OpenGraphDatabase(cfg)
	if db == nil {
		_, _ = afmt.R.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	for _, name := range args.Domains.Slice() {
		for i, assoc := range getAssociations(name, start, db) {
			if i != 0 {
				_, _ = fmt.Println()
			}

			var rel string
			switch v := assoc.Asset.(type) {
			case *oamreg.DomainRecord:
				rel = "registrant_contact"
				_, _ = afmt.G.Fprintln(color.Output, v.Domain)
				if verbose {
					_, _ = fmt.Fprintf(color.Output, "%s%s\n%s%s\n", afmt.Blue("Name: "),
						afmt.Green(v.Name), afmt.Blue("Expiration: "), afmt.Green(v.ExpirationDate))
				}
			case *oamreg.AutnumRecord:
				rel = "registrant"
				_, _ = afmt.G.Fprintln(color.Output, v.Handle)
				if verbose {
					_, _ = fmt.Fprintf(color.Output, "%s%s\n%s%s\n%s%s\n", afmt.Blue("Name: "), afmt.Green(v.Name),
						afmt.Blue("Status: "), afmt.Green(v.Status[0]), afmt.Blue("Updated: "), afmt.Green(v.UpdatedDate))
				}
			case *oamreg.IPNetRecord:
				rel = "registrant"
				_, _ = afmt.G.Fprintln(color.Output, v.CIDR.String())
				if verbose {
					_, _ = fmt.Fprintf(color.Output, "%s%s\n%s%s\n%s%s\n", afmt.Blue("Name: "), afmt.Green(v.Name),
						afmt.Blue("Status: "), afmt.Green(v.Status[0]), afmt.Blue("Updated: "), afmt.Green(v.UpdatedDate))
				}
			}

			if verbose {
				_, _ = afmt.B.Fprintln(color.Output, "Registrant|")
				printContactInfo(assoc, rel, start, db)
				_, _ = fmt.Println()
			}
		}
	}
}

func printContactInfo(assoc *dbt.Entity, regrel string, since time.Time, db repository.Repository) {
	var contact *dbt.Entity

	if edges, err := db.OutgoingEdges(assoc, since, regrel); err == nil && len(edges) > 0 {
		if a, err := db.FindEntityById(edges[0].ToEntity.ID); err == nil && a != nil {
			contact = a
		}
	}
	if contact == nil {
		return
	}

	for _, out := range []string{"person", "organization", "location", "phone", "email"} {
		if edges, err := db.OutgoingEdges(contact, since, out); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if a, err := db.FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
					_, _ = fmt.Fprintf(color.Output, "%s%s%s\n",
						afmt.Blue(string(a.Asset.AssetType())), afmt.Blue(": "), afmt.Green(a.Asset.Key()))
				}
			}
		}
	}
}

func getAssociations(name string, since time.Time, db repository.Repository) []*dbt.Entity {
	var results []*dbt.Entity

	fqdns, err := db.FindEntitiesByContent(&oamdns.FQDN{Name: name}, since)
	if err != nil || len(fqdns) == 0 {
		return results
	}

	var assets []*dbt.Entity
	for _, fqdn := range fqdns {
		if edges, err := db.OutgoingEdges(fqdn, since, "registration"); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if a, err := db.FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
					assets = append(assets, a)
				}
			}
		}
	}

	set := stringset.New()
	defer set.Close()

	for _, asset := range assets {
		set.Insert(asset.ID)
	}

	for findings := assets; len(findings) > 0; {
		assets = findings
		findings = []*dbt.Entity{}

		for _, a := range assets {
			if edges, err := db.OutgoingEdges(a, since, "associated_with"); err == nil && len(edges) > 0 {
				for _, edge := range edges {
					asset, err := db.FindEntityById(edge.ToEntity.ID)
					if err != nil || asset == nil {
						continue
					}

					if !set.Has(asset.ID) {
						set.Insert(asset.ID)
						findings = append(findings, asset)
						results = append(results, asset)
					}
				}
			}
		}
	}

	return results
}
