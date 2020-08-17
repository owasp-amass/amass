// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/fatih/color"
)

const (
	dbUsageMsg = "db [options]"
)

type dbArgs struct {
	Domains stringset.Set
	Enum    int
	Options struct {
		DemoMode         bool
		IPs              bool
		IPv4             bool
		IPv6             bool
		ListEnumerations bool
		ASNTableSummary  bool
		DiscoveredNames  bool
		NoColor          bool
		ShowAll          bool
		Silent           bool
		Sources          bool
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

	dbCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	dbCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	dbCommand.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	dbCommand.IntVar(&args.Enum, "enum", 0, "Identify an enumeration via an index from the listing")
	dbCommand.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	dbCommand.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.ListEnumerations, "list", false, "Numbered list of enums filtered on provided domains")
	dbCommand.BoolVar(&args.Options.Sources, "src", false, "Print data sources for the discovered names")
	dbCommand.BoolVar(&args.Options.ASNTableSummary, "summary", false, "Print Just ASN Table Summary")
	dbCommand.BoolVar(&args.Options.DiscoveredNames, "names", false, "Print Just Discovered Names")
	dbCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	dbCommand.BoolVar(&args.Options.ShowAll, "show", false, "Print the results for the enumeration index + domains provided")
	dbCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	dbCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
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
		color.Output = ioutil.Discard
		color.Error = ioutil.Discard
	}

	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			return
		}
		args.Domains.InsertMany(list...)
	}

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

	db := openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	defer db.Close()

	if args.Options.ListEnumerations {
		listEvents(&args, db)
		return
	}

	if args.Options.ShowAll {
		args.Options.DiscoveredNames = true
		args.Options.ASNTableSummary = true
	}

	if !args.Options.DiscoveredNames && !args.Options.ASNTableSummary {
		commandUsage(dbUsageMsg, dbCommand, dbBuf)
		return
	}

	// Get all the UUIDs for events that have information in scope
	uuids := eventUUIDs(args.Domains.Slice(), db)
	if len(uuids) == 0 {
		r.Fprintln(color.Error, "Failed to find the domains of interest in the database")
		os.Exit(1)
	}

	// Put the events in chronological order
	uuids, _, _ = orderedEvents(uuids, db)
	if len(uuids) == 0 {
		r.Fprintln(color.Error, "Failed to sort the events")
		os.Exit(1)
	}

	// Select the enumeration that the user specified
	if args.Enum > 0 && len(uuids) > args.Enum {
		uuids = []string{uuids[args.Enum]}
	}

	if args.Options.ASNTableSummary {
		healASInfo(uuids, db)
	}

	// Create the in-memory graph database
	memDB, err := memGraphForEvents(uuids, db)
	if err != nil {
		r.Fprintln(color.Error, err.Error())
		os.Exit(1)
	}

	showEventData(&args, uuids, memDB)
}

func listEvents(args *dbArgs, db *graph.Graph) {
	domains := args.Domains.Slice()
	events := eventUUIDs(domains, db)

	if len(events) == 0 {
		r.Fprintln(color.Error, "No enumerations found within the provided scope")
		return
	}

	events, earliest, latest := orderedEvents(events, db)
	// Check if the user has requested the list of enumerations
	for i := range events {
		if i != 0 {
			g.Println()
		}

		g.Printf("%d) %s -> %s: ", i+1, earliest[i].Format(timeFormat), latest[i].Format(timeFormat))
		// Print out the scope for this enumeration
		for x, domain := range db.EventDomains(events[i]) {
			if x != 0 {
				g.Print(", ")
			}
			g.Print(domain)
		}
		g.Println()
	}
}

func showEventData(args *dbArgs, uuids []string, db *graph.Graph) {
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
			outfile.Sync()
			outfile.Close()
		}()
		outfile.Truncate(0)
		outfile.Seek(0, 0)
	}

	tags := make(map[string]int)
	asns := make(map[int]*format.ASNSummaryData)
	for _, out := range getEventOutput(uuids, db) {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}

		out.Addresses = format.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
		if len(out.Addresses) == 0 {
			continue
		}

		total++
		format.UpdateSummaryData(out, tags, asns)
		source, name, ips := format.OutputLineParts(out, args.Options.Sources,
			args.Options.IPs || args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)

		if ips != "" {
			ips = " " + ips
		}

		if args.Options.DiscoveredNames {
			if outfile != nil {
				fmt.Fprintf(outfile, "%s%s%s\n", source, name, ips)
			} else {
				fmt.Fprintf(color.Output, "%s%s%s\n", blue(source), green(name), yellow(ips))
			}
		}
	}

	if total == 0 {
		r.Println("No names were discovered")
	} else if args.Options.ASNTableSummary {
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

		format.FprintEnumerationSummary(out, total, tags, asns, args.Options.DemoMode)
		color.NoColor = status
	}
}
