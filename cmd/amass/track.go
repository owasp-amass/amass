// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
)

const (
	timeFormat    = "01/02 15:04:05 2006 MST"
	trackUsageMsg = "track [options] -d domain"
)

type trackArgs struct {
	Domains *stringset.Set
	Last    int
	Since   string
	Options struct {
		History bool
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
	trackCommand.IntVar(&args.Last, "last", 0, "The number of recent enumerations to include in the tracking")
	trackCommand.StringVar(&args.Since, "since", "", "Exclude all enumerations before (format: "+timeFormat+")")
	trackCommand.BoolVar(&args.Options.History, "history", false, "Show the difference between all enumeration pairs")
	trackCommand.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	trackCommand.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
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

	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = ioutil.Discard
		color.Error = ioutil.Discard
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

	rand.Seed(time.Now().UTC().UnixNano())

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
	db := openGraphDatabase(args.Filepaths.Directory, cfg)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	defer db.Close()

	// Get all the UUIDs for events that have information in scope
	uuids := db.EventsInScope(context.TODO(), args.Domains.Slice()...)
	if len(uuids) == 0 {
		r.Fprintln(color.Error, "Failed to find the domains of interest in the database")
		os.Exit(1)
	}

	var earliest, latest []time.Time
	// Put the events in chronological order
	uuids, earliest, latest = orderedEvents(context.TODO(), uuids, db)
	if len(uuids) == 0 {
		r.Fprintln(color.Error, "Failed to sort the events")
		os.Exit(1)
	}

	// The default is to use all the enumerations available
	if args.Last == 0 {
		args.Last = len(uuids)
	}

	var begin int
	// Filter out enumerations that begin before the start date/time
	if args.Since != "" {
		for i := len(uuids) - 1; i >= 0; i-- {
			if earliest[i].Before(start) {
				break
			}
			begin++
		}
	} else { // Or the number of enumerations from the end of the timeline
		if args.Last > len(uuids) {
			r.Fprintf(color.Error, "%d enumerations are not available\n", args.Last)
			os.Exit(1)
		}

		begin = args.Last
	}
	begin = len(uuids) - begin
	uuids = uuids[begin:]
	earliest = earliest[begin:]
	latest = latest[begin:]

	cache := cacheWithData()
	if len(uuids) == 1 {
		printOneEvent(uuids, args.Domains.Slice(), earliest[0], latest[0], db, cache)
		return
	} else if args.Options.History {
		completeHistoryOutput(uuids, args.Domains.Slice(), earliest, latest, db, cache)
		return
	}
	cumulativeOutput(uuids, args.Domains.Slice(), earliest, latest, db, cache)
}

func printOneEvent(uuid, domains []string, earliest, latest time.Time, db *netmap.Graph, cache *requests.ASNCache) {
	one := getScopedOutput(uuid, domains, db, cache)

	blueLine()
	fmt.Fprintf(color.Output, "%s\t%s%s%s\n%s\t%s%s%s\n", blue("Between"),
		yellow(earliest.Format(timeFormat)), blue(" -> "), yellow(latest.Format(timeFormat)),
		blue("and"), yellow(earliest.Format(timeFormat)), blue(" -> "), yellow(latest.Format(timeFormat)))
	blueLine()

	for _, d := range diffEnumOutput([]*requests.Output{}, one) {
		fmt.Fprintln(color.Output, d)
	}
}

func cumulativeOutput(uuids, domains []string, ea, la []time.Time, db *netmap.Graph, cache *requests.ASNCache) {
	idx := len(uuids) - 1
	cum := getScopedOutput(uuids[:idx], domains, db, cache)

	blueLine()
	fmt.Fprintf(color.Output, "%s\t%s%s%s\n%s\t%s%s%s\n", blue("Between"),
		yellow(ea[0].Format(timeFormat)), blue(" -> "), yellow(la[0].Format(timeFormat)),
		blue("and"), yellow(ea[idx].Format(timeFormat)), blue(" -> "), yellow(la[idx].Format(timeFormat)))
	blueLine()

	var updates bool
	out := getScopedOutput([]string{uuids[idx]}, domains, db, cache)
	for _, d := range diffEnumOutput(cum, out) {
		updates = true
		fmt.Fprintln(color.Output, d)
	}
	if !updates {
		g.Println("No differences discovered")
	}
}

func getScopedOutput(uuids, domains []string, db *netmap.Graph, cache *requests.ASNCache) []*requests.Output {
	var output []*requests.Output

	for _, out := range getEventOutput(context.TODO(), uuids, false, db, cache) {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}

		output = append(output, out)
	}

	return output
}

func completeHistoryOutput(uuids, domains []string, ea, la []time.Time, db *netmap.Graph, cache *requests.ASNCache) {
	var prev string

	for i, uuid := range uuids {
		if prev == "" {
			prev = uuid
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
		out1 := getScopedOutput([]string{prev}, domains, db, cache)
		out2 := getScopedOutput([]string{uuid}, domains, db, cache)
		for _, d := range diffEnumOutput(out1, out2) {
			updates = true
			fmt.Fprintln(color.Output, d)
		}
		if !updates {
			g.Println("No differences discovered")
		}
		prev = uuid
	}
}

func blueLine() {
	for i := 0; i < 8; i++ {
		b.Fprint(color.Output, "----------")
	}
	fmt.Println()
}

func diffEnumOutput(older, newer []*requests.Output) []string {
	oldmap := make(map[string]*requests.Output)
	newmap := make(map[string]*requests.Output)

	for _, o := range older {
		oldmap[o.Name] = o
	}
	for _, o := range newer {
		newmap[o.Name] = o
	}

	var diff []string
	for name, o := range newmap {
		o2, found := oldmap[name]
		if !found {
			diff = append(diff, fmt.Sprintf("%s%s %s", blue("Found: "),
				green(name), yellow(lineOfAddresses(o.Addresses))))
			continue
		}

		if !compareAddresses(o.Addresses, o2.Addresses) {
			diff = append(diff, fmt.Sprintf("%s%s\n\t%s\t%s\n\t%s\t%s", blue("Moved: "),
				green(name), blue(" from "), yellow(lineOfAddresses(o2.Addresses)),
				blue(" to "), yellow(lineOfAddresses(o.Addresses))))
		}
	}

	for name, o := range oldmap {
		if _, found := newmap[name]; !found {
			diff = append(diff, fmt.Sprintf("%s%s %s", blue("Removed: "),
				green(name), yellow(lineOfAddresses(o.Addresses))))
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
