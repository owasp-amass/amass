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

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/graph"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/stringset"
	"github.com/OWASP/Amass/utils"
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
		Show             bool
		Sources          bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		Import     string
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
	dbCommand.BoolVar(&args.Options.Show, "show", false, "Print the results for the enumeration index + domains provided")
	dbCommand.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	dbCommand.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	dbCommand.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	dbCommand.StringVar(&args.Filepaths.Import, "import", "", "Import an Amass data operations JSON file to the graph database")

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

	cfg := config.New()
	// Check if a configuration file was provided, and if so, load the settings
	if _, err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
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

	// Import of data operations from a JSON file to the database
	if args.Filepaths.Import != "" {
		if err := inputDataOperations(&args, db); err != nil {
			r.Fprintf(color.Error, "Input data operations: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if args.Options.ListEnumerations {
		listEnumerations(&args, db)
		return
	}

	if args.Options.Show {
		showEnumeration(&args, db)
		return
	}

	commandUsage(dbUsageMsg, dbCommand, dbBuf)
}

func openGraphDatabase(dir string, cfg *config.Config) graph.DataHandler {
	var db graph.DataHandler
	// Attempt to connect to an Amass graph database
	if cfg.GremlinURL != "" {
		if g := graph.NewGremlin(cfg.GremlinURL, cfg.GremlinUser, cfg.GremlinPass, nil); g != nil {
			db = g
		}
	} else {
		if d := config.OutputDirectory(dir); d != "" {
			// Check that the graph database directory exists
			if finfo, err := os.Stat(d); !os.IsNotExist(err) && finfo.IsDir() {
				if g := graph.NewGraph(d); g != nil {
					db = g
				}
			}
		}
	}
	return db
}

func inputDataOperations(args *dbArgs, db graph.DataHandler) error {
	f, err := os.Open(args.Filepaths.Import)
	if err != nil {
		return fmt.Errorf("Failed to open the input file: %v", err)
	}

	opts, err := graph.ParseDataOpts(f)
	if err != nil {
		return errors.New("Failed to parse the provided data operations")
	}

	err = graph.DataOptsDriver(opts, db)
	if err != nil {
		return fmt.Errorf("Failed to populate the database: %v", err)
	}
	return nil
}

func listEnumerations(args *dbArgs, db graph.DataHandler) {
	domains := args.Domains.ToSlice()
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

func showEnumeration(args *dbArgs, db graph.DataHandler) {
	domains := args.Domains.ToSlice()
	var total int
	tags := make(map[string]int)
	asns := make(map[int]*utils.ASNSummaryData)
	for _, out := range getEnumOutput(args.Enum, domains, db) {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}

		out.Addresses = utils.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
		if len(out.Addresses) == 0 {
			continue
		}

		total++
		utils.UpdateSummaryData(out, tags, asns)
		source, name, ips := utils.OutputLineParts(out, args.Options.Sources,
			args.Options.IPs || args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)

		if ips != "" {
			ips = " " + ips
		}

		fmt.Fprintf(color.Output, "%s%s%s\n", blue(source), green(name), yellow(ips))
	}
	if total == 0 {
		r.Println("No names were discovered")
	} else {
		utils.PrintEnumerationSummary(total, tags, asns, args.Options.DemoMode)
	}
}

func getEnumOutput(id int, domains []string, db graph.DataHandler) []*requests.Output {
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

	filter := utils.NewStringFilter()
	for i := len(enums) - 1; i >= 0; i-- {
		for _, out := range db.GetOutput(enums[i], true) {
			if !filter.Duplicate(out.Name) {
				output = append(output, out)
			}
		}
	}
	return output
}

func getUniqueDBOutput(id string, domains []string, db graph.DataHandler) []*requests.Output {
	var output []*requests.Output
	filter := utils.NewStringFilter()

	for _, out := range db.GetOutput(id, true) {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}
		if !filter.Duplicate(out.Name) {
			output = append(output, out)
		}
	}
	return output
}

func enumIndexToID(e int, domains []string, db graph.DataHandler) string {
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
func mostRecentEnumID(domains []string, db graph.DataHandler) string {
	var uuid string
	var latest time.Time

	for i, enum := range db.EnumerationList() {
		if len(domains) > 0 {
			var found bool
			scope := db.EnumerationDomains(enum)

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

		_, l := db.EnumerationDateRange(enum)
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
func enumIDs(domains []string, db graph.DataHandler) []string {
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

func orderedEnumsAndDateRanges(enums []string, db graph.DataHandler) ([]string, []time.Time, []time.Time) {
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
