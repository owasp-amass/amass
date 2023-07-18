// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v3/format"
	"github.com/owasp-amass/amass/v3/requests"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/network"
)

const (
	dbUsageMsg = "db [options]"
)

type dbArgs struct {
	Domains *stringset.Set
	Enum    int
	Options struct {
		DemoMode        bool
		IPs             bool
		IPv4            bool
		IPv6            bool
		ASNTableSummary bool
		DiscoveredNames bool
		NoColor         bool
		ShowAll         bool
		Silent          bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		TermOut    string
	}
}

func runDBCommand(clArgs []string) {
	var args dbArgs
	var help1, help2 bool
	dbCommand := flag.NewFlagSet("db", flag.ContinueOnError)

	dbBuf := new(bytes.Buffer)
	dbCommand.SetOutput(dbBuf)
	args.Domains = stringset.New()
	defer args.Domains.Close()

	dbCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	dbCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	dbCommand.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	dbCommand.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	dbCommand.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.ASNTableSummary, "summary", false, "Print Just ASN Table Summary")
	dbCommand.BoolVar(&args.Options.DiscoveredNames, "names", false, "Print Just Discovered Names")
	dbCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	dbCommand.BoolVar(&args.Options.ShowAll, "show", false, "Print the results for the enumeration index + domains provided")
	dbCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	dbCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
	dbCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	dbCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	dbCommand.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")

	if len(clArgs) < 1 {
		commandUsage(dbUsageMsg, dbCommand, dbBuf)
		return
	}
	if err := dbCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(dbUsageMsg, dbCommand, dbBuf)
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

	db := openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	if args.Options.ShowAll {
		args.Options.DiscoveredNames = true
		args.Options.ASNTableSummary = true
	}
	if !args.Options.DiscoveredNames && !args.Options.ASNTableSummary {
		commandUsage(dbUsageMsg, dbCommand, dbBuf)
		return
	}

	var asninfo bool
	if args.Options.ASNTableSummary {
		asninfo = true
	}

	showEventData(&args, asninfo, db)
}

func showEventData(args *dbArgs, asninfo bool, db *netmap.Graph) {
	var total int
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

	var cache *requests.ASNCache
	if asninfo {
		cache = requests.NewASNCache()
		if err := fillCache(cache, db); err != nil {
			r.Printf("Failed to populate the ASN cache: %v\n", err)
			return
		}
	}

	asns := make(map[int]*format.ASNSummaryData)
	for _, out := range getEventOutput(context.Background(), domains, asninfo, db, cache) {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}

		out.Addresses = format.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
		if l := len(out.Addresses); (args.Options.IPs || args.Options.IPv4 || args.Options.IPv6) && l == 0 {
			continue
		} else if l > 0 {
			format.UpdateSummaryData(out, asns)
		}

		total++
		name, ips := format.OutputLineParts(out, args.Options.IPs || args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)
		if ips != "" {
			ips = " " + ips
		}

		if args.Options.DiscoveredNames {
			var written bool
			if outfile != nil {
				fmt.Fprintf(outfile, "%s%s\n", name, ips)
				written = true
			}
			if !written {
				fmt.Fprintf(color.Output, "%s%s\n", green(name), yellow(ips))
			}
		}
	}

	if total == 0 {
		r.Println("No names were discovered")
		return
	}
	if args.Options.ASNTableSummary {
		var out io.Writer
		status := color.NoColor

		if outfile != nil {
			out = outfile
			color.NoColor = true
		} else if args.Options.ShowAll {
			out = color.Error
		} else {
			out = color.Output
		}

		format.FprintEnumerationSummary(out, total, asns, args.Options.DemoMode)
		color.NoColor = status
	}
}

func fillCache(cache *requests.ASNCache, db *netmap.Graph) error {
	start := time.Now().Add(-730 * time.Hour)
	assets, err := db.DB.FindByType(oam.ASN, start)
	if err != nil {
		return err
	}

	for _, a := range assets {
		as, ok := a.Asset.(network.AutonomousSystem)
		if !ok {
			continue
		}

		desc := db.ReadASDescription(context.Background(), as.Number, start)
		if desc == "" {
			continue
		}

		for _, prefix := range db.ReadASPrefixes(context.Background(), as.Number, start) {
			first, cidr, err := net.ParseCIDR(prefix)
			if err != nil {
				continue
			}
			if ones, _ := cidr.Mask.Size(); ones == 0 {
				continue
			}

			cache.Update(&requests.ASNRequest{
				Address:     first.String(),
				ASN:         as.Number,
				Prefix:      cidr.String(),
				Description: desc,
			})
		}
	}
	return nil
}
