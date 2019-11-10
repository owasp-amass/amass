// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/fatih/color"
)

const (
	timeFormat    = "01/02 15:04:05 2006 MST"
	trackUsageMsg = "track [options] -d domain"
)

type trackArgs struct {
	Domains stringset.Set
	Last    int
	Since   string
	Options struct {
		History bool
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

	trackBuf := new(bytes.Buffer)
	trackCommand.SetOutput(trackBuf)

	trackCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	trackCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	trackCommand.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	trackCommand.IntVar(&args.Last, "last", 0, "The number of recent enumerations to include in the tracking")
	trackCommand.StringVar(&args.Since, "since", "", "Exclude all enumerations before (format: "+timeFormat+")")
	trackCommand.BoolVar(&args.Options.History, "history", false, "Show the difference between all enumeration pairs")
	trackCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	trackCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	trackCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")

	if len(clArgs) < 1 {
		commandUsage(trackUsageMsg, trackCommand, trackBuf)
		return
	}

	if err := trackCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(trackUsageMsg, trackCommand, trackBuf)
		return
	}

	// Some input validation
	if args.Since != "" && args.Last != 0 {
		r.Fprintln(color.Error, "The since flag cannot be used with the last or all flags")
		os.Exit(1)
	}
	if args.Last > 0 && args.Last < 2 {
		r.Fprintln(color.Error, "Tracking requires more than one enumeration")
		os.Exit(1)
	}
	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		args.Domains.InsertMany(list...)
	}
	if len(args.Domains) == 0 {
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

	rand.Seed(time.Now().UTC().UnixNano())

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

	// Connect with the graph database containing the enumeration data
	db := openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	defer db.Close()

	// Obtain the enumerations that include the provided domain(s)
	enums := enumIDs(args.Domains.Slice(), db)

	// There needs to be at least two enumerations to proceed
	if len(enums) < 2 {
		r.Fprintln(color.Error, "Tracking requires more than one enumeration")
		os.Exit(1)
	}
	// The default is to use all the enumerations available
	if args.Last == 0 {
		args.Last = len(enums)
	}

	var end int
	enums, earliest, latest := orderedEnumsAndDateRanges(enums, db)
	// Filter out enumerations that begin before the start date/time
	if args.Since != "" {
		for i := len(enums) - 1; i >= 0; i-- {
			if !earliest[i].Before(start) {
				break
			}
			end++
		}
	} else { // Or the number of enumerations from the end of the timeline
		if args.Last > len(enums) {
			r.Fprintf(color.Error, "%d enumerations are not available\n", args.Last)
			os.Exit(1)
		}

		end = args.Last
	}
	enums = enums[:end]
	earliest = earliest[:end]
	latest = latest[:end]

	if args.Options.History {
		completeHistoryOutput(args.Domains.Slice(), enums, earliest, latest, db)
		return
	}
	cumulativeOutput(args.Domains.Slice(), enums, earliest, latest, db)
}

func cumulativeOutput(domains []string, enums []string, ea, la []time.Time, db *graph.Graph) {
	idx := len(enums) - 1
	filter := stringset.NewStringFilter()

	var cum []*requests.Output
	for i := idx - 1; i >= 0; i-- {
		for _, out := range getUniqueDBOutput(enums[i], domains, db) {
			if domainNameInScope(out.Name, domains) && !filter.Duplicate(out.Name) {
				cum = append(cum, out)
			}
		}
	}

	blueLine()
	fmt.Fprintf(color.Output, "%s\t%s%s%s\n%s\t%s%s%s\n", blue("Between"),
		yellow(ea[0].Format(timeFormat)), blue(" -> "), yellow(la[0].Format(timeFormat)),
		blue("and"), yellow(ea[idx].Format(timeFormat)), blue(" -> "), yellow(la[idx].Format(timeFormat)))
	blueLine()

	var updates bool
	out := getUniqueDBOutput(enums[idx], domains, db)
	for _, d := range diffEnumOutput(cum, out) {
		updates = true
		fmt.Fprintln(color.Output, d)
	}
	if !updates {
		g.Println("No differences discovered")
	}
}

func completeHistoryOutput(domains []string, enums []string, ea, la []time.Time, db *graph.Graph) {
	var prev string

	for i, enum := range enums {
		if prev == "" {
			prev = enum
			continue
		}
		if i != 1 {
			fmt.Println()
		}

		blueLine()
		fmt.Fprintf(color.Output, "%s\t%s%s%s\n%s\t%s%s%s\n", blue("Between"),
			yellow(ea[i-1].Format(timeFormat)), blue(" -> "), yellow(la[i-1].Format(timeFormat)),
			blue("and"), yellow(ea[i].Format(timeFormat)), blue(" -> "), yellow(la[i].Format(timeFormat)))
		blueLine()

		var updates bool
		out1 := getUniqueDBOutput(prev, domains, db)
		out2 := getUniqueDBOutput(enum, domains, db)
		for _, d := range diffEnumOutput(out1, out2) {
			updates = true
			fmt.Fprintln(color.Output, d)
		}
		if !updates {
			g.Println("No differences discovered")
		}
		prev = enum
	}
}

func blueLine() {
	for i := 0; i < 8; i++ {
		b.Fprint(color.Output, "----------")
	}
	fmt.Println()
}

func diffEnumOutput(out1, out2 []*requests.Output) []string {
	omap1 := make(map[string]*requests.Output)
	omap2 := make(map[string]*requests.Output)

	for _, o := range out1 {
		omap1[o.Name] = o
	}
	for _, o := range out2 {
		omap2[o.Name] = o
	}

	handled := make(map[string]struct{})
	var diff []string
	for _, o := range out1 {
		handled[o.Name] = struct{}{}

		if _, found := omap2[o.Name]; !found {
			diff = append(diff, fmt.Sprintf("%s%s %s", blue("Found: "),
				green(o.Name), yellow(lineOfAddresses(o.Addresses))))
			continue
		}

		o2 := omap2[o.Name]
		if !compareAddresses(o.Addresses, o2.Addresses) {
			diff = append(diff, fmt.Sprintf("%s%s\n\t%s\t%s\n\t%s\t%s", blue("Moved: "),
				green(o.Name), blue(" from "), yellow(lineOfAddresses(o2.Addresses)),
				blue(" to "), yellow(lineOfAddresses(o.Addresses))))
		}
	}

	for _, o := range out2 {
		if _, found := handled[o.Name]; found {
			continue
		}

		if _, found := omap1[o.Name]; !found {
			diff = append(diff, fmt.Sprintf("%s%s %s", blue("Removed: "),
				green(o.Name), yellow(lineOfAddresses(o.Addresses))))
		}
	}
	return diff
}

func lineOfAddresses(addrs []requests.AddressInfo) string {
	var line string

	for i, addr := range addrs {
		if i != 0 {
			line = line + ","
		}
		line = line + addr.Address.String()
	}
	return line
}

func compareAddresses(addr1, addr2 []requests.AddressInfo) bool {
	for _, a1 := range addr1 {
		var found bool

		for _, a2 := range addr2 {
			if a1.Address.Equal(a2.Address) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
