// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/graph/db"
	"github.com/OWASP/Amass/v3/requests"
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
		ShowAll          bool
		Sources          bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
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
	dbCommand.BoolVar(&args.Options.ShowAll, "show", false, "Print the results for the enumeration index + domains provided")
	dbCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	dbCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	dbCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")

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
		listEnumerations(&args, db)
		return
	}

	if args.Options.ShowAll {
		args.Options.DiscoveredNames = true
		args.Options.ASNTableSummary = true
	}

	if args.Options.DiscoveredNames || args.Options.ASNTableSummary {
		showEnumeration(&args, db)
		return
	}

	commandUsage(dbUsageMsg, dbCommand, dbBuf)
}

func openGraphDatabase(dir string, cfg *config.Config) *graph.Graph {
	var gDB *graph.Graph
	// Attempt to connect to an Amass graph database
	/*if cfg.GremlinURL != "" {
		if g := graph.NewGremlin(cfg.GremlinURL, cfg.GremlinUser, cfg.GremlinPass, nil); g != nil {
			db = g
		}
	} else {*/
	if d := config.OutputDirectory(dir); d != "" {
		// Check that the graph database directory exists
		if finfo, err := os.Stat(d); !os.IsNotExist(err) && finfo.IsDir() {
			if g := graph.NewGraph(db.NewCayleyGraph(d)); g != nil {
				gDB = g
			}
		}
	}
	//}
	return gDB
}

func listEnumerations(args *dbArgs, db *graph.Graph) {
	domains := args.Domains.Slice()
	enums := enumIDs(domains, db)
	if len(enums) == 0 {
		r.Fprintln(color.Error, "No enumerations found within the provided scope")
		return
	}

	enums, earliest, latest := orderedEnumsAndDateRanges(enums, db)
	// Check if the user has requested the list of enumerations
	for i := range enums {
		if i != 0 {
			g.Println()
		}
		g.Printf("%d) %s -> %s: ", i+1, earliest[i].Format(timeFormat), latest[i].Format(timeFormat))
		// Print out the scope for this enumeration
		for x, domain := range db.EventDomains(enums[i]) {
			if x != 0 {
				g.Print(", ")
			}
			g.Print(domain)
		}
		g.Println()
	}
}

func showEnumeration(args *dbArgs, db *graph.Graph) {
	domains := args.Domains.Slice()
	var total int
	tags := make(map[string]int)
	asns := make(map[int]*format.ASNSummaryData)
	for _, out := range getEnumOutput(args.Enum, domains, db) {
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
			fmt.Fprintf(color.Output, "%s%s%s\n", blue(source), green(name), yellow(ips))
		}
	}
	if total == 0 {
		r.Println("No names were discovered")
	} else if args.Options.ASNTableSummary {
		format.PrintEnumerationSummary(total, tags, asns, args.Options.DemoMode)
	}
}

func getEnumOutput(id int, domains []string, db *graph.Graph) []*requests.Output {
	var output []*requests.Output

	if id > 0 {
		enum := enumIndexToID(id, domains, db)
		if enum == "" {
			r.Fprintln(color.Error, "No enumerations found within the provided scope")
			return output
		}
		return getUniqueDBOutput(enum, domains, db)
	}

	enums := enumIDs(domains, db)
	if len(enums) == 0 {
		return output
	}

	enums, _, _ = orderedEnumsAndDateRanges(enums, db)
	if len(enums) == 0 {
		return output
	}

	filter := stringset.NewStringFilter()
	for i := len(enums) - 1; i >= 0; i-- {
		for _, out := range db.GetOutput(enums[i]) {
			if !filter.Duplicate(out.Name) {
				output = append(output, out)
			}
		}
	}
	return output
}

func getUniqueDBOutput(id string, domains []string, db *graph.Graph) []*requests.Output {
	var output []*requests.Output
	filter := stringset.NewStringFilter()

	for _, out := range db.GetOutput(id) {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}
		if !filter.Duplicate(out.Name) {
			output = append(output, out)
		}
	}
	return output
}

func enumIndexToID(e int, domains []string, db *graph.Graph) string {
	enums := enumIDs(domains, db)
	if len(enums) == 0 {
		return ""
	}

	enums, _, _ = orderedEnumsAndDateRanges(enums, db)
	if len(enums) >= e {
		return enums[e-1]
	}
	return ""
}

// Get the UUID for the most recent enumeration
func mostRecentEnumID(domains []string, db *graph.Graph) string {
	var uuid string
	var latest time.Time

	for i, enum := range db.EventList() {
		if len(domains) > 0 {
			var found bool
			scope := db.EventDomains(enum)

			for _, domain := range domains {
				if domainNameInScope(domain, scope) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		_, l := db.EventDateRange(enum)
		if i == 0 {
			latest = l
			uuid = enum
		} else if l.After(latest) {
			uuid = enum
		}
	}
	return uuid
}

// Obtain the enumeration IDs that include the provided domain
func enumIDs(domains []string, db *graph.Graph) []string {
	var enums []string

	for _, id := range db.EventList() {
		if len(domains) == 0 {
			enums = append(enums, id)
			continue
		}

		scope := db.EventDomains(id)

		for _, domain := range domains {
			if domainNameInScope(domain, scope) {
				enums = append(enums, id)
				break
			}
		}
	}
	return enums
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

func orderedEnumsAndDateRanges(enums []string, db *graph.Graph) ([]string, []time.Time, []time.Time) {
	sort.Slice(enums, func(i, j int) bool {
		var less bool

		e1, l1 := db.EventDateRange(enums[i])
		e2, l2 := db.EventDateRange(enums[j])
		if l1.After(l2) || e2.Before(e1) {
			less = true
		}
		return less
	})

	var earliest, latest []time.Time
	for _, enum := range enums {
		e, l := db.EventDateRange(enum)

		earliest = append(earliest, e)
		latest = append(latest, l)
	}
	return enums, earliest, latest
}
