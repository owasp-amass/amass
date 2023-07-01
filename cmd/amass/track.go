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
	"os"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v3/config"
	"github.com/owasp-amass/amass/v3/requests"
)

const (
	timeFormat    = "01/02 15:04:05 2006 MST"
	trackUsageMsg = "track [options] -d domain"
)

type trackArgs struct {
	Domains *stringset.Set
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
		color.Output = io.Discard
		color.Error = io.Discard
	}
	// Some input validation
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

	cache := cacheWithData()
	cumulativeOutput(args.Domains.Slice(), db, cache)
}

func cumulativeOutput(domains []string, db *netmap.Graph, cache *requests.ASNCache) {
	cum := getScopedOutput(domains, db, cache)

	var updates bool
	out := getScopedOutput(domains, db, cache)
	for _, d := range diffEnumOutput(cum, out) {
		updates = true
		fmt.Fprintln(color.Output, d)
	}
	if !updates {
		g.Println("No differences discovered")
	}
}

func getScopedOutput(domains []string, db *netmap.Graph, cache *requests.ASNCache) []*requests.Output {
	var output []*requests.Output

	for _, out := range getEventOutput(context.TODO(), domains, false, db, cache) {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}
		output = append(output, out)
	}
	return output
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
