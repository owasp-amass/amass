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
	"github.com/owasp-amass/amass/v4/config"
	assetdb "github.com/owasp-amass/asset-db"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
)

const emailsUsageMsg = "emails [options] -d domain"

type emailsArgs struct {
	Domains *stringset.Set
	Enum    int
	Options struct {
		DemoMode bool
		NoColor  bool
		Silent   bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		TermOut    string
	}
}

func runEmailsCommand(clArgs []string) {
	var args emailsArgs
	var help1, help2 bool
	emailsCommand := flag.NewFlagSet("emails", flag.ContinueOnError)

	args.Domains = stringset.New()
	defer args.Domains.Close()

	emailsBuf := new(bytes.Buffer)
	emailsCommand.SetOutput(emailsBuf)

	emailsCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	emailsCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	emailsCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	emailsCommand.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	emailsCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	emailsCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	emailsCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
	emailsCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	emailsCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	emailsCommand.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")

	var usage = func() {
		g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), emailsUsageMsg)
		emailsCommand.PrintDefaults()
		g.Fprintln(color.Error, emailsBuf.String())
	}

	if len(clArgs) < 1 {
		usage()
		return
	}
	if err := emailsCommand.Parse(clArgs); err != nil {
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
			return
		}
		args.Domains.InsertMany(list...)
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

	db := openGraphDatabase(cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	showEmails(&args, db)
}

func showEmails(args *emailsArgs, db *assetdb.AssetDB) {
	var err error
	var outfile *os.File
	domains := args.Domains.Slice()

	if args.Filepaths.TermOut != "" {
		outfile, err = os.OpenFile(args.Filepaths.TermOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the text output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			_ = outfile.Sync()
			_ = outfile.Close()
		}()
		_ = outfile.Truncate(0)
		_, _ = outfile.Seek(0, 0)
	}

	addrs := getAddresses(db, domains)
	if len(addrs) == 0 {
		r.Println("No email addresses were discovered")
		return
	}

	for _, addr := range addrs {
		g.Println(addr)
	}
}

func getAddresses(db *assetdb.AssetDB, domains []string) []string {
	if len(domains) == 0 {
		return nil
	}

	qtime := time.Time{}
	filter := stringset.New()
	defer filter.Close()

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, &domain.FQDN{Name: d})
	}

	assets, err := db.FindByScope(fqdns, qtime)
	if err != nil {
		return nil
	}

	var addrs []string
	for _, a := range assets {
		if n, ok := a.Asset.(*contact.EmailAddress); ok && !filter.Has(n.Address) {
			addrs = append(addrs, n.Address)
			filter.Insert(n.Address)
		}
	}
	return addrs
}
