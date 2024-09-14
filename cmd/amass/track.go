// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

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
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

const trackUsageMsg = "track [options] [-since '" + timeFormat + "'] " + "-d domain"

type trackArgs struct {
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

func runTrackCommand(clArgs []string) {
	var args trackArgs
	var help1, help2 bool
	trackCommand := flag.NewFlagSet("track", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	trackBuf := new(bytes.Buffer)
	trackCommand.SetOutput(trackBuf)

	trackCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	trackCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	trackCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	trackCommand.StringVar(&args.Since, "since", "", "Exclude all assets discovered before (format: "+timeFormat+")")
	trackCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	trackCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	trackCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	trackCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	trackCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing registered domain names")

	var usage = func() {
		g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), trackUsageMsg)
		trackCommand.PrintDefaults()
		g.Fprintln(color.Error, trackBuf.String())
	}

	if len(clArgs) < 1 {
		usage()
		return
	}
	if err := trackCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
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
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		args.Domains.InsertMany(list...)
	}
	if args.Domains.Len() == 0 {
		r.Fprintln(color.Error, "No root domain names were provided")
		os.Exit(1)
	}

	var err error
	var start time.Time
	if args.Since != "" {
		start, err = time.Parse(timeFormat, args.Since)
		if err != nil {
			r.Fprintf(color.Error, "%s is not in the correct format: %s\n", args.Since, timeFormat)
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
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}
	// Connect with the graph database containing the enumeration data
	db := openGraphDatabase(cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	for _, name := range getNewNames(args.Domains.Slice(), start, db) {
		g.Fprintln(color.Output, name)
	}
}

func getNewNames(domains []string, since time.Time, db *assetdb.AssetDB) []string {
	if len(domains) == 0 {
		return []string{}
	}

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, &domain.FQDN{Name: d})
	}

	if !since.IsZero() {
		since = since.UTC()
	}

	assets, err := db.FindByScope(fqdns, since)
	if err != nil {
		return []string{}
	}

	if since.IsZero() {
		var latest time.Time
		for _, a := range assets {
			if _, ok := a.Asset.(*domain.FQDN); ok && a.LastSeen.After(latest) {
				latest = a.LastSeen
			}
		}
		since = latest.Truncate(24 * time.Hour)
	}

	res := stringset.New()
	defer res.Close()

	for _, a := range assets {
		if n, ok := a.Asset.(*domain.FQDN); ok && !res.Has(n.Name) &&
			(a.CreatedAt.Equal(since) || a.CreatedAt.After(since)) &&
			(a.LastSeen.Equal(since) || a.LastSeen.After(since)) {
			res.Insert(n.Name)
		}
	}

	return res.Slice()
}
