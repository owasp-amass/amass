// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package track

import (
	"bytes"
	"flag"
	"io"
	"os"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	amassdb "github.com/owasp-amass/amass/v5/internal/db"
	"github.com/owasp-amass/amass/v5/internal/tools"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

const (
	TimeFormat  = "01/02 15:04:05 2006 MST"
	UsageMsg    = "[options] [-since '" + TimeFormat + "'] " + "-d domain"
	Description = "Analyze OAM data to identify newly discovered assets"
)

type Args struct {
	Help    bool
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

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("track", flag.ContinueOnError)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	fs.StringVar(&args.Since, "since", "", "Exclude all assets discovered before (format: "+TimeFormat+")")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file")
	fs.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	fs.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing registered domain names")
	return fs
}

func CLIWorkflow(cmdName string, clArgs []string) {
	var args Args
	args.Domains = stringset.New()
	defer args.Domains.Close()

	fs := NewFlagset(&args, flag.ContinueOnError)
	trackBuf := new(bytes.Buffer)
	fs.SetOutput(trackBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", cmdName, UsageMsg)

		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, trackBuf.String())
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

	for _, name := range getNewNames(args.Domains.Slice(), start, db) {
		_, _ = afmt.G.Fprintln(color.Output, name)
	}
}

func getNewNames(domains []string, since time.Time, db repository.Repository) []string {
	if len(domains) == 0 {
		return []string{}
	}

	var assets []*dbt.Entity
	for _, d := range domains {
		if ents, err := db.FindEntitiesByContent(&oamdns.FQDN{Name: d}, since); err == nil && len(ents) == 1 {
			if n, err := amassdb.FindByFQDNScope(db, ents[0], since); err == nil && len(n) > 0 {
				assets = append(assets, n...)
			}
		}
	}
	if len(assets) == 0 {
		return []string{}
	}

	if since.IsZero() {
		var latest time.Time

		for _, a := range assets {
			if _, ok := a.Asset.(*oamdns.FQDN); ok && a.LastSeen.After(latest) {
				latest = a.LastSeen
			}
		}

		since = latest.Truncate(24 * time.Hour)
	}

	res := stringset.New()
	defer res.Close()

	for _, a := range assets {
		if n, ok := a.Asset.(*oamdns.FQDN); ok && !res.Has(n.Name) &&
			(a.CreatedAt.Equal(since) || a.CreatedAt.After(since)) &&
			(a.LastSeen.Equal(since) || a.LastSeen.After(since)) {
			res.Insert(n.Name)
		}
	}

	return res.Slice()
}
