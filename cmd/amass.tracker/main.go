// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
	homedir "github.com/mitchellh/go-homedir"
)

const (
	timeFormat string = "01/02 15:04:05 2006 MST"
)

var (
	// Colors used to ease the reading of program output
	y      = color.New(color.FgHiYellow)
	g      = color.New(color.FgHiGreen)
	r      = color.New(color.FgHiRed)
	b      = color.New(color.FgHiBlue)
	fgR    = color.New(color.FgRed)
	fgY    = color.New(color.FgYellow)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	// Command-line switches and provided parameters
	help        = flag.Bool("h", false, "Show the program usage message")
	list        = flag.Bool("list", false, "Print information for all available enumerations")
	vprint      = flag.Bool("version", false, "Print the version number of this Amass binary")
	dir         = flag.String("dir", "", "Path to the directory containing the graph database")
	last        = flag.Int("last", 0, "The number of recent enumerations to include in the tracking")
	startStr    = flag.String("start", "", "Exclude all enumerations before (format: "+timeFormat+")")
	history     = flag.Bool("history", false, "Show the difference between all enumeration pairs")
	domainspath = flag.String("df", "", "Path to a file providing root domain names")
)

func main() {
	var domains utils.ParseStrings

	defaultBuf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(defaultBuf)
	flag.Usage = func() {
		amass.PrintBanner()
		g.Fprintf(color.Error, "Usage: %s [options] -d domain\n\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Fprintln(color.Error, defaultBuf.String())
	}
	flag.Var(&domains, "d", "Domain names separated by commas (can be used multiple times)")
	flag.Parse()

	// Some input validation
	if *help || len(os.Args) == 1 {
		flag.Usage()
		return
	}
	if *vprint {
		fmt.Fprintf(color.Error, "version %s\n", amass.Version)
		os.Exit(1)
	}
	if *startStr != "" && *last != 0 {
		r.Fprintln(color.Error, "The start flag cannot be used with the last or all flags")
		os.Exit(1)
	}
	if *last == 1 {
		r.Fprintln(color.Error, "Tracking requires more than one enumeration")
		os.Exit(1)
	}
	if *domainspath != "" {
		list, err := core.GetListFromFile(*domainspath)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		domains = utils.UniqueAppend(domains, list...)
	}
	if len(domains) == 0 {
		r.Fprintln(color.Error, "No root domain names were provided")
		os.Exit(1)
	}

	var err error
	var start time.Time
	if *startStr != "" {
		start, err = time.Parse(timeFormat, *startStr)
		if err != nil {
			r.Fprintf(color.Error, "%s is not in the correct format: %s\n", *startStr, timeFormat)
			os.Exit(1)
		}
	}

	rand.Seed(time.Now().UTC().UnixNano())

	if *dir == "" {
		path, err := homedir.Dir()
		if err != nil {
			r.Fprintln(color.Error, "Failed to obtain the user home directory")
			os.Exit(1)
		}
		*dir = filepath.Join(path, handlers.DefaultGraphDBDirectory)
	}
	// Check that the default graph database directory exists
	if finfo, err := os.Stat(*dir); os.IsNotExist(err) || !finfo.IsDir() {
		r.Fprintln(color.Error, "Failed to open the graph database")
		os.Exit(1)
	}

	graph := handlers.NewGraph(*dir)
	if graph == nil {
		r.Fprintln(color.Error, "Failed to open the graph database")
		os.Exit(1)
	}

	var enums []string
	// Obtain the enumerations that include the provided domain
	for _, e := range graph.EnumerationList() {
		for _, domain := range domains {
			if enumContainsDomain(e, domain, graph) {
				enums = append(enums, e)
				break
			}
		}
	}

	// There needs to be at least two enumerations to proceed
	if len(enums) < 2 {
		r.Fprintln(color.Error, "Tracking requires more than one enumeration")
		os.Exit(1)
	}
	// The default is to use all the enumerations available
	if *last == 0 {
		*last = len(enums)
	}

	var begin int
	enums, earliest, latest := orderedEnumsAndDateRanges(enums, graph)
	// Filter out enumerations that begin before the start date/time
	if *startStr != "" {
		for _, e := range earliest {
			if !e.Before(start) {
				break
			}
			begin++
		}
	} else { // Or the number of enumerations from the end of the timeline
		if len(enums) < *last {
			r.Fprintf(color.Error, "%d enumerations are not available\n", *last)
			os.Exit(1)
		}

		begin = len(enums) - *last
	}
	enums = enums[begin:]
	earliest = earliest[begin:]
	latest = latest[begin:]

	// Check if the user has requested the list of enumerations
	if *list {
		for i := range enums {
			g.Printf("%d) %s -> %s\n", i+1, earliest[i].Format(timeFormat), latest[i].Format(timeFormat))
		}
		return
	}

	if *history {
		completeHistoryOutput(domains, enums, earliest, latest, graph)
		return
	}
	cumulativeOutput(domains, enums, earliest, latest, graph)
}

func cumulativeOutput(domains []string, enums []string, ea, la []time.Time, h handlers.DataHandler) {
	idx := len(enums) - 1
	filter := utils.NewStringFilter()

	var cum []*core.Output
	for i := idx - 1; i >= 0; i-- {
		for _, out := range getEnumDataInScope(domains, enums[i], h) {
			if !filter.Duplicate(out.Name) {
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
	out := getEnumDataInScope(domains, enums[idx], h)
	for _, d := range diffEnumOutput(cum, out) {
		updates = true
		fmt.Fprintln(color.Output, d)
	}
	if !updates {
		g.Println("No differences discovered")
	}
}

func completeHistoryOutput(domains []string, enums []string, ea, la []time.Time, h handlers.DataHandler) {
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
		out1 := getEnumDataInScope(domains, prev, h)
		out2 := getEnumDataInScope(domains, enum, h)
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

func getEnumDataInScope(domains []string, enum string, h handlers.DataHandler) []*core.Output {
	var out []*core.Output

	for _, o := range h.GetOutput(enum, true) {
		for _, domain := range domains {
			if strings.HasSuffix(o.Name, domain) {
				out = append(out, o)
				break
			}
		}
	}
	return out
}

func diffEnumOutput(out1, out2 []*core.Output) []string {
	omap1 := make(map[string]*core.Output)
	omap2 := make(map[string]*core.Output)

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
			diff = append(diff, fmt.Sprintf("%s%s %s", blue("Removed: "),
				green(o.Name), yellow(lineOfAddresses(o.Addresses))))
			continue
		}

		o2 := omap2[o.Name]
		if !compareAddresses(o.Addresses, o2.Addresses) {
			diff = append(diff, fmt.Sprintf("%s%s\n\t%s\t%s\n\t%s\t%s", blue("Moved: "),
				green(o.Name), blue(" from "), yellow(lineOfAddresses(o.Addresses)),
				blue(" to "), yellow(lineOfAddresses(o2.Addresses))))
		}
	}

	for _, o := range out2 {
		if _, found := handled[o.Name]; found {
			continue
		}

		if _, found := omap1[o.Name]; !found {
			diff = append(diff, fmt.Sprintf("%s%s %s", blue("Found: "),
				green(o.Name), yellow(lineOfAddresses(o.Addresses))))
		}
	}
	return diff
}

func lineOfAddresses(addrs []core.AddressInfo) string {
	var line string

	for i, addr := range addrs {
		if i != 0 {
			line = line + ","
		}
		line = line + addr.Address.String()
	}
	return line
}

func compareAddresses(addr1, addr2 []core.AddressInfo) bool {
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

func orderedEnumsAndDateRanges(enums []string, h handlers.DataHandler) ([]string, []time.Time, []time.Time) {
	sort.Slice(enums, func(i, j int) bool {
		var less bool

		e1, l1 := h.EnumerationDateRange(enums[i])
		e2, l2 := h.EnumerationDateRange(enums[j])
		if l2.After(l1) || e1.Before(e2) {
			less = true
		}
		return less
	})

	var earliest, latest []time.Time
	for _, enum := range enums {
		e, l := h.EnumerationDateRange(enum)

		earliest = append(earliest, e)
		latest = append(latest, l)
	}
	return enums, earliest, latest
}

func enumContainsDomain(enum, domain string, h handlers.DataHandler) bool {
	var found bool

	for _, d := range h.EnumerationDomains(enum) {
		if d == domain {
			found = true
			break
		}
	}
	return found
}
