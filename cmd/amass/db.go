// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

const (
	dbUsageMsg = "db [options]"
)

type dbArgs struct {
	Domains utils.ParseStrings
	Enum    int
	Options struct {
		DemoMode         bool
		IPs              bool
		IPv4             bool
		IPv6             bool
		ListEnumerations bool
		Show bool
		Sources          bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		Input      string
	}
}

func runDBCommand(clArgs []string) {
	var args dbArgs
	var help1, help2 bool
	dbCommand := flag.NewFlagSet("db", flag.ExitOnError)

	dbBuf := new(bytes.Buffer)
	dbCommand.SetOutput(dbBuf)

	dbCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	dbCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	dbCommand.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	dbCommand.IntVar(&args.Enum, "enum", 0, "Identify an enumeration via an index from the listing")
	dbCommand.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	dbCommand.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	dbCommand.BoolVar(&args.Options.ListEnumerations, "list", false, "Show the enumerations that include identified domains")
	dbCommand.BoolVar(&args.Options.Sources, "src", false, "Print data sources for the discovered names")
	dbCommand.BoolVar(&args.Options.Show, "show", false, "Print the results for the enumeration index + domains provided")
	dbCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	dbCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	dbCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	dbCommand.StringVar(&args.Filepaths.Input, "i", "", "Import an Amass data operations JSON file to the graph database")

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

	config := new(core.Config)
	// Check if a configuration file was provided, and if so, load the settings
	if acquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, config) {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = config.Dir
		}
	}

	db := openGraphDatabase(args.Filepaths.Directory, config)
	if db == nil {
		r.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}
	defer db.Close()

	// Input of data operations from a JSON file to the database
	if args.Filepaths.Input != "" {
		if err := inputDataOperations(&args, db); err != nil {
			r.Fprintf(color.Error, "Input data operations: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if args.Options.ListEnumerations {
		listEnumerations(args.Domains, db)
		return
	}

	if args.Options.Show && args.Enum > 0 {
		showEnumeration(&args, db)
		return
	}

	commandUsage(dbUsageMsg, dbCommand, dbBuf)
}

func openGraphDatabase(dir string, config *core.Config) handlers.DataHandler {
	var db handlers.DataHandler
	// Attempt to connect to an Amass graph database
	/*if args.Options.Neo4j {
		neo, err := handlers.NewNeo4j(args.URL, args.User, args.Password, nil)
		if err != nil {
			db = neo
		}
	} else */
	if config.GremlinURL != "" {
		if g := handlers.NewGremlin(config.GremlinURL, config.GremlinUser, config.GremlinPass, nil); g != nil {
			db = g
		}
	} else {
		if d := outputDirectory(dir); d != "" {
			// Check that the graph database directory exists
			if finfo, err := os.Stat(d); !os.IsNotExist(err) && finfo.IsDir() {
				if graph := handlers.NewGraph(d); graph != nil {
					db = graph
				}
			}
		}
	}
	return db
}

func inputDataOperations(args *dbArgs, db handlers.DataHandler) error {
	f, err := os.Open(args.Filepaths.Input)
	if err != nil {
		return fmt.Errorf("Failed to open the input file: %v", err)
	}

	opts, err := handlers.ParseDataOpts(f)
	if err != nil {
		return errors.New("Failed to parse the provided data operations")
	}

	err = handlers.DataOptsDriver(opts, db)
	if err != nil {
		return fmt.Errorf("Failed to populate the database: %v", err)
	}
	return nil
}

func listEnumerations(domains []string, db handlers.DataHandler) {
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
		for x, domain := range db.EnumerationDomains(enums[i]) {
			if x != 0 {
				g.Print(", ")
			}
			g.Print(domain)
		}
		g.Println()
	}
}

func showEnumeration(args *dbArgs, db handlers.DataHandler) {
	id := enumIndexToID(args.Enum, args.Domains, db)
	if id == "" {
		r.Fprintln(color.Error, "No enumerations found within the provided scope")
		return
	}

	var total int
	tags := make(map[string]int)
	asns := make(map[int]*amass.ASNSummaryData)
	for _, out := range db.GetOutput(id, true) {
		if len(args.Domains) > 0 && !domainNameInScope(out.Name, args.Domains) {
			continue
		}

		out.Addresses = amass.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
		if len(out.Addresses) == 0 {
			continue
		}

		total++
		amass.UpdateSummaryData(out, tags, asns)
		source, name, ips := amass.OutputLineParts(out, args.Options.Sources,
			args.Options.IPs || args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)

		if ips != "" {
			ips = " " + ips
		}

		fmt.Fprintf(color.Output, "%s%s%s\n", blue(source), green(name), yellow(ips))
	}
	if total == 0 {
		r.Println("No names were discovered")
	} else {
		amass.PrintEnumerationSummary(total, tags, asns, args.Options.DemoMode)
	}
}

func enumIndexToID(e int, domains []string, db handlers.DataHandler) string {
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

// Obtain the enumeration IDs that include the provided domain
func enumIDs(domains []string, db handlers.DataHandler) []string {
	var enums []string

	for _, e := range db.EnumerationList() {
		if len(domains) == 0 {
			enums = append(enums, e)
			continue
		}

		scope := db.EnumerationDomains(e)

		for _, domain := range domains {
			if domainNameInScope(domain, scope) {
				enums = append(enums, e)
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

func orderedEnumsAndDateRanges(enums []string, db handlers.DataHandler) ([]string, []time.Time, []time.Time) {
	sort.Slice(enums, func(i, j int) bool {
		var less bool

		e1, l1 := db.EnumerationDateRange(enums[i])
		e2, l2 := db.EnumerationDateRange(enums[j])
		if l1.After(l2) || e2.Before(e1) {
			less = true
		}
		return less
	})

	var earliest, latest []time.Time
	for _, enum := range enums {
		e, l := db.EnumerationDateRange(enum)

		earliest = append(earliest, e)
		latest = append(latest, l)
	}
	return enums, earliest, latest
}
