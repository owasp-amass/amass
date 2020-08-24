// Copyright © by Jeff Foley 2017-2020. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// In-depth Attack Surface Mapping and Asset Discovery
//  +----------------------------------------------------------------------------+
//  | * * * ░░░░░░░░░░░░░░░░░░░░  OWASP Amass  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ |
//  +----------------------------------------------------------------------------+
//  |      .+++:.            :                             .+++.                 |
//  |    +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+   |
//  |   &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&   |
//  |  +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8         |
//  |  8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:       |
//  |  WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:     |
//  |  #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8    |
//  |  o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.  |
//  |   WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o  |
//  |   :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+  |
//  |    :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&   |
//  |      +o&&&&+.                                                    +oooo.    |
//  +----------------------------------------------------------------------------+
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/graphdb"
	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/fatih/color"
)

const (
	mainUsageMsg         = "intel|enum|viz|track|db|dns [options]"
	exampleConfigFileURL = "https://github.com/OWASP/Amass/blob/master/examples/config.ini"
	userGuideURL         = "https://github.com/OWASP/Amass/blob/master/doc/user_guide.md"
	tutorialURL          = "https://github.com/OWASP/Amass/blob/master/doc/tutorial.md"
)

var (
	// Colors used to ease the reading of program output
	g      = color.New(color.FgHiGreen)
	r      = color.New(color.FgHiRed)
	b      = color.New(color.FgHiBlue)
	fgR    = color.New(color.FgRed)
	fgY    = color.New(color.FgYellow)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	red    = color.New(color.FgHiRed).SprintFunc()
)

func commandUsage(msg string, cmdFlagSet *flag.FlagSet, errBuf *bytes.Buffer) {
	format.PrintBanner()
	g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), msg)
	cmdFlagSet.PrintDefaults()
	g.Fprintln(color.Error, errBuf.String())

	if msg == mainUsageMsg {
		g.Fprintf(color.Error, "\nSubcommands: \n\n")
		g.Fprintf(color.Error, "\t%-11s - Discover targets for enumerations\n", "amass intel")
		g.Fprintf(color.Error, "\t%-11s - Perform enumerations and network mapping\n", "amass enum")
		g.Fprintf(color.Error, "\t%-11s - Visualize enumeration results\n", "amass viz")
		g.Fprintf(color.Error, "\t%-11s - Track differences between enumerations\n", "amass track")
		g.Fprintf(color.Error, "\t%-11s - Manipulate the Amass graph database\n", "amass db")
		g.Fprintf(color.Error, "\t%-11s - Resolve DNS names at high performance\n\n", "amass dns")
	}

	g.Fprintf(color.Error, "The user's guide can be found here: \n%s\n\n", userGuideURL)
	g.Fprintf(color.Error, "An example configuration file can be found here: \n%s\n\n", exampleConfigFileURL)
	g.Fprintf(color.Error, "The Amass tutorial can be found here: \n%s\n\n", tutorialURL)
}

func main() {
	var version, help1, help2 bool
	mainFlagSet := flag.NewFlagSet("amass", flag.ContinueOnError)

	defaultBuf := new(bytes.Buffer)
	mainFlagSet.SetOutput(defaultBuf)

	mainFlagSet.BoolVar(&help1, "h", false, "Show the program usage message")
	mainFlagSet.BoolVar(&help2, "help", false, "Show the program usage message")
	mainFlagSet.BoolVar(&version, "version", false, "Print the version number of this Amass binary")

	if len(os.Args) < 2 {
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		return
	}

	if err := mainFlagSet.Parse(os.Args[1:]); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		return
	}
	if version {
		fmt.Fprintf(color.Error, "%s\n", format.Version)
		return
	}

	switch os.Args[1] {
	case "db":
		runDBCommand(os.Args[2:])
	case "dns":
		runDNSCommand(os.Args[2:])
	case "enum":
		runEnumCommand(os.Args[2:])
	case "intel":
		runIntelCommand(os.Args[2:])
	case "track":
		runTrackCommand(os.Args[2:])
	case "viz":
		runVizCommand(os.Args[2:])
	default:
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		os.Exit(1)
	}
}

// GetAllSourceInfo returns the names of all Amass data sources.
func GetAllSourceInfo() []string {
	var names []string

	sys, err := systems.NewLocalSystem(config.NewConfig())
	if err != nil {
		return names
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys))

	for _, src := range sys.DataSources() {
		names = append(names, fmt.Sprintf("%-20s\t%s", src.String(), src.Type()))
	}

	sys.Shutdown()
	return names
}

func createOutputDirectory(cfg *config.Config) {
	// Prepare output file paths
	dir := config.OutputDirectory(cfg.Dir)
	if dir == "" {
		r.Fprintln(color.Error, "Failed to obtain the output directory")
		os.Exit(1)
	}
	// If the directory does not yet exist, create it
	if err := os.MkdirAll(dir, 0755); err != nil {
		r.Fprintf(color.Error, "Failed to create the directory: %v\n", err)
		os.Exit(1)
	}
}

func generateCategoryMap(sys systems.System) map[string][]string {
	catToSources := make(map[string][]string)

	for _, src := range sys.DataSources() {
		t := src.Type()

		catToSources[t] = append(catToSources[t], src.String())
	}

	return catToSources
}

func expandCategoryNames(names []string, categories map[string][]string) []string {
	var newnames []string

	for _, name := range names {
		if _, found := categories[name]; found {
			newnames = append(newnames, categories[name]...)
			continue
		}

		newnames = append(newnames, name)
	}

	return newnames
}

func openGraphDatabase(dir string, cfg *config.Config) *graph.Graph {
	// Attempt to connect to a Gremlin Amass graph database
	if cfg.GremlinURL != "" {
		gremlin := graphdb.NewGremlin(cfg.GremlinURL, cfg.GremlinUser, cfg.GremlinPass)

		if gremlin != nil {
			if g := graph.NewGraph(gremlin); g != nil {
				return g
			}
		}
	}

	// Check that the graph database directory exists
	if d := config.OutputDirectory(dir); d != "" {
		if finfo, err := os.Stat(d); !os.IsNotExist(err) && finfo.IsDir() {
			if g := graph.NewGraph(graphdb.NewCayleyGraph(d, false)); g != nil {
				return g
			}
		}
	}

	return nil
}

func orderedEvents(events []string, db *graph.Graph) ([]string, []time.Time, []time.Time) {
	sort.Slice(events, func(i, j int) bool {
		var less bool

		e1, l1 := db.EventDateRange(events[i])
		e2, l2 := db.EventDateRange(events[j])
		if l1.After(l2) || e2.Before(e1) {
			less = true
		}
		return less
	})

	var earliest, latest []time.Time
	for _, event := range events {
		e, l := db.EventDateRange(event)

		earliest = append(earliest, e)
		latest = append(latest, l)
	}

	return events, earliest, latest
}

// Obtain the enumeration IDs that include the provided domain
func eventUUIDs(domains []string, db *graph.Graph) []string {
	var uuids []string

	for _, id := range db.EventList() {
		if len(domains) == 0 {
			uuids = append(uuids, id)
			continue
		}

		var count int
		surface := db.EventDomains(id)
		for _, domain := range surface {
			if domainNameInScope(domain, domains) {
				count++
			}
		}

		if count == len(domains) {
			uuids = append(uuids, id)
		}
	}

	return uuids
}

func memGraphForEvents(uuids []string, from *graph.Graph) (*graph.Graph, error) {
	db := graph.NewGraph(graphdb.NewCayleyGraphMemory())
	if db == nil {
		return nil, errors.New("Failed to create the in-memory graph database")
	}

	// Migrate the event data into the in-memory graph database
	if err := migrateAllEvents(uuids, from, db); err != nil {
		return nil, fmt.Errorf("Failed to move the data into the in-memory graph database: %v", err)
	}

	return db, nil
}

func migrateAllEvents(uuids []string, from, to *graph.Graph) error {
	for _, uuid := range uuids {
		if err := from.MigrateEvent(uuid, to); err != nil {
			return err
		}
	}

	return nil
}

func getEventOutput(uuids []string, db *graph.Graph) []*requests.Output {
	var output []*requests.Output
	cache := net.NewASNCache()
	filter := stringfilter.NewStringFilter()

	for i := len(uuids) - 1; i >= 0; i-- {
		output = append(output, db.EventOutput(uuids[i], filter, true, cache)...)
	}

	return output
}

func domainNameInScope(name string, scope []string) bool {
	var discovered bool

	n := strings.ToLower(strings.TrimSpace(name))
	for _, d := range scope {
		d = strings.ToLower(d)

		if n == d || strings.HasSuffix(n, "."+d) {
			discovered = true
			break
		}
	}

	return discovered
}

func healASInfo(uuids []string, db *graph.Graph) {
	cache := net.NewASNCache()
	db.ASNCacheFill(cache)

	cfg := config.NewConfig()
	cfg.LocalDatabase = false
	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys))
	defer sys.Shutdown()

	bus := eventbus.NewEventBus()
	bus.Subscribe(requests.NewASNTopic, cache.Update)
	defer bus.Unsubscribe(requests.NewASNTopic, cache.Update)
	ctx := context.WithValue(context.Background(), requests.ContextConfig, cfg)
	ctx = context.WithValue(ctx, requests.ContextEventBus, bus)

	for _, uuid := range uuids {
		for _, out := range db.EventOutput(uuid, nil, false, cache) {
			for _, a := range out.Addresses {
				if r := cache.AddrSearch(a.Address.String()); r != nil {
					db.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, uuid)
					continue
				}

				for _, src := range sys.DataSources() {
					src.ASNRequest(ctx, &requests.ASNRequest{Address: a.Address.String()})
				}

				for cache.AddrSearch(a.Address.String()) == nil {
					time.Sleep(time.Second)
				}

				if r := cache.AddrSearch(a.Address.String()); r != nil {
					db.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, uuid)
				}
			}
		}
	}
}
