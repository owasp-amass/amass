// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

const (
	exampleConfigFileURL = "https://github.com/OWASP/Amass/blob/master/examples/amass_config.ini"
)

var (
	finished chan struct{}
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
	help          = flag.Bool("h", false, "Show the program usage message")
	list          = flag.Bool("list", false, "Print the names of all available data sources")
	vprint        = flag.Bool("version", false, "Print the version number of this Amass binary")
	dir           = flag.String("dir", "", "Path to the directory containing the output files")
	config        = flag.String("config", "", "Path to the INI configuration file. Additional details below")
	maxdns        = flag.Int("max-dns-queries", 0, "Maximum number of concurrent DNS queries")
	unresolved    = flag.Bool("include-unresolvable", false, "Output DNS names that did not resolve")
	ips           = flag.Bool("ip", false, "Show the IP addresses for discovered names")
	ipv4          = flag.Bool("ipv4", false, "Show the IPv4 addresses for discovered names")
	ipv6          = flag.Bool("ipv6", false, "Show the IPv6 addresses for discovered names")
	brute         = flag.Bool("brute", false, "Execute brute forcing after searches")
	active        = flag.Bool("active", false, "Attempt zone transfers and certificate name grabs")
	norecursive   = flag.Bool("norecursive", false, "Turn off recursive brute forcing")
	minrecursive  = flag.Int("min-for-recursive", 0, "Number of subdomain discoveries before recursive brute forcing")
	passive       = flag.Bool("passive", false, "Disable DNS resolution of names and dependent features")
	noalts        = flag.Bool("noalts", false, "Disable generation of altered names")
	sources       = flag.Bool("src", false, "Print data sources for the discovered names")
	wordlist      = flag.String("w", "", "Path to a different wordlist file")
	allpath       = flag.String("oA", "", "Path prefix used for naming all output files")
	logpath       = flag.String("log", "", "Path to the log file where errors will be written")
	outpath       = flag.String("o", "", "Path to the text output file")
	jsonpath      = flag.String("json", "", "Path to the JSON output file")
	datapath      = flag.String("do", "", "Path to data operations output file")
	domainspath   = flag.String("df", "", "Path to a file providing root domain names")
	excludepath   = flag.String("ef", "", "Path to a file providing data sources to exclude")
	includepath   = flag.String("if", "", "Path to a file providing data sources to include")
	resolvepath   = flag.String("rf", "", "Path to a file providing preferred DNS resolvers")
	blacklistpath = flag.String("blf", "", "Path to a file providing blacklisted subdomains")
)

func main() {
	var ports utils.ParseInts
	var domains, included, excluded, resolvers, blacklist utils.ParseStrings

	defaultBuf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(defaultBuf)
	flag.Usage = func() {
		amass.PrintBanner()
		g.Fprintf(color.Error, "Usage: %s [options] <-d domain>\n\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Fprintln(color.Error, defaultBuf.String())
		g.Fprintf(color.Error, "An example configuration file can be found here: \n%s\n\n", exampleConfigFileURL)
	}

	flag.Var(&ports, "p", "Ports separated by commas (default: 443)")
	flag.Var(&domains, "d", "Domain names separated by commas (can be used multiple times)")
	flag.Var(&excluded, "exclude", "Data source names separated by commas to be excluded")
	flag.Var(&included, "include", "Data source names separated by commas to be included")
	flag.Var(&resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
	flag.Var(&blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	flag.Parse()

	if *help || len(os.Args) == 1 {
		flag.Usage()
		return
	}
	// Check if the user has requested the data source names
	if *list {
		enum := amass.NewEnumeration()

		for _, name := range enum.GetAllSourceNames() {
			g.Println(name)
		}
		return
	}
	// Some input validation
	if *vprint {
		fmt.Fprintf(color.Error, "version %s\n", amass.Version)
		os.Exit(1)
	}
	if *passive && *ips {
		r.Fprintln(color.Error, "IP addresses cannot be provided without DNS resolution")
		os.Exit(1)
	}
	if *passive && *brute {
		r.Fprintln(color.Error, "Brute forcing cannot be performed without DNS resolution")
		os.Exit(1)
	}

	var err error
	var words []string
	// Obtain parameters from provided input files
	if *wordlist != "" {
		words, err = core.GetListFromFile(*wordlist)
		if err != nil {
			r.Fprintf(color.Error, "%v\n", err)
		}
	}
	if *blacklistpath != "" {
		list, err := core.GetListFromFile(*blacklistpath)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the blacklist file: %v\n", err)
			os.Exit(1)
		}
		blacklist = utils.UniqueAppend(blacklist, list...)
	}
	if *excludepath != "" {
		list, err := core.GetListFromFile(*excludepath)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the exclude file: %v\n", err)
			os.Exit(1)
		}
		excluded = utils.UniqueAppend(excluded, list...)
	}
	if *includepath != "" {
		list, err := core.GetListFromFile(*includepath)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the include file: %v\n", err)
			os.Exit(1)
		}
		included = utils.UniqueAppend(included, list...)
	}
	if *domainspath != "" {
		list, err := core.GetListFromFile(*domainspath)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			os.Exit(1)
		}
		domains = utils.UniqueAppend(domains, list...)
	}
	if *resolvepath != "" {
		list, err := core.GetListFromFile(*resolvepath)
		if err != nil {
			r.Fprintf(color.Error, "Failed to parse the resolver file: %v\n", err)
			os.Exit(1)
		}
		resolvers = utils.UniqueAppend(resolvers, list...)
	}
	// Check if a config file was provided that has DNS resolvers specified
	if *config != "" {
		if r, err := core.GetResolversFromSettings(*config); err == nil {
			resolvers = utils.UniqueAppend(resolvers, r...)
		}
	}
	if len(resolvers) > 0 {
		amass.SetCustomResolvers(resolvers)
	}

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	rLog, wLog := io.Pipe()
	enum := amass.NewEnumeration()
	enum.Config.Log = log.New(wLog, "", log.Lmicroseconds)
	// Check if a configuration file was provided, and if so, load the settings
	if *config != "" {
		if err := enum.Config.LoadSettings(*config); err != nil {
			r.Fprintf(color.Error, "Configuration file error: %v\n", err)
			os.Exit(1)
		}
	}
	// Setup the amass enumeration settings
	if *dir != "" {
		enum.Config.Dir = *dir
	}
	if *maxdns != 0 {
		enum.Config.MaxDNSQueries = *maxdns
	}
	if len(words) != 0 {
		enum.Config.Wordlist = words
	}
	if *brute {
		enum.Config.BruteForcing = true
	}
	if *noalts {
		enum.Config.Alterations = false
	}
	if *norecursive {
		enum.Config.Recursive = false
	}
	if *minrecursive != 0 {
		enum.Config.MinForRecursive = *minrecursive
	}
	if *active {
		enum.Config.Active = true
	}
	if *unresolved {
		enum.Config.IncludeUnresolvable = true
	}
	if *passive {
		enum.Config.Passive = true
	}
	if len(blacklist) != 0 {
		enum.Config.Blacklist = blacklist
	}

	enum.Config.DisabledDataSources = utils.UniqueAppend(
		enum.Config.DisabledDataSources, compileDisabledSources(enum, included, excluded)...)

	// Attempt to add the provided domains to the configuration
	enum.Config.AddDomains(domains)
	if len(enum.Config.Domains()) == 0 {
		r.Fprintln(color.Error, "No root domain names were provided")
		os.Exit(1)
	}

	// Prepare output file paths
	*dir = enum.Config.Dir
	if *dir == "" {
		*dir = handlers.DefaultGraphDBDirectory
	}
	// If the directory does not yet exist, create it
	if err = os.MkdirAll(*dir, 0755); err != nil {
		r.Fprintf(color.Error, "Failed to create the directory: %v\n", err)
		os.Exit(1)
	}
	logfile := filepath.Join(*dir, "amass.log")
	if *logpath != "" {
		logfile = *logpath
	}
	txtfile := filepath.Join(*dir, "amass.txt")
	if *outpath != "" {
		txtfile = *outpath
	}
	jsonfile := filepath.Join(*dir, "amass.json")
	if *jsonpath != "" {
		jsonfile = *jsonpath
	}
	datafile := filepath.Join(*dir, "amass_data.json")
	if *datapath != "" {
		datafile = *datapath
	}
	if *allpath != "" {
		logfile = *allpath + ".log"
		txtfile = *allpath + ".txt"
		jsonfile = *allpath + ".json"
		datafile = *allpath + "_data.json"
	}

	go writeLogsAndMessages(rLog, logfile)
	if !enum.Config.Passive && datafile != "" {
		fileptr, err := os.OpenFile(datafile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the data operations output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			fileptr.Sync()
			fileptr.Close()
		}()
		fileptr.Truncate(0)
		fileptr.Seek(0, 0)
		enum.Config.DataOptsWriter = fileptr
	}

	var outptr, jsonptr *os.File
	if txtfile != "" {
		outptr, err = os.OpenFile(txtfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the text output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			outptr.Sync()
			outptr.Close()
		}()
		outptr.Truncate(0)
		outptr.Seek(0, 0)
	}

	var enc *json.Encoder
	if jsonfile != "" {
		jsonptr, err = os.OpenFile(jsonfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the JSON output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			jsonptr.Sync()
			jsonptr.Close()
		}()
		jsonptr.Truncate(0)
		jsonptr.Seek(0, 0)
		enc = json.NewEncoder(jsonptr)
	}

	// Kick off the output management goroutine
	finished = make(chan struct{})
	go func() {
		var total int
		tags := make(map[string]int)
		asns := make(map[int]*amass.ASNSummaryData)
		// Collect all the names returned by the enumeration
		for out := range enum.Output {
			out.Addresses = desiredAddrTypes(out.Addresses)
			if !enum.Config.Passive && len(out.Addresses) <= 0 {
				continue
			}

			total++
			amass.UpdateSummaryData(out, tags, asns)
			source, name, ips := amass.OutputLineParts(out, *sources, *ips || *ipv4 || *ipv6)
			fmt.Fprintf(color.Output, "%s%s %s\n", blue(source), green(name), yellow(ips))
			// Handle writing the line to a specified output file
			if outptr != nil {
				fmt.Fprintf(outptr, "%s%s %s\n", source, name, ips)
			}
			// Handle encoding the result as JSON
			if jsonptr != nil {
				enc.Encode(out)
			}
		}
		if total == 0 {
			r.Println("No names were discovered")
		} else {
			amass.PrintEnumerationSummary(total, tags, asns)
		}
		close(finished)
	}()
	// Start the enumeration process
	go signalHandler(enum)
	if err := enum.Start(); err != nil {
		r.Println(err)
		os.Exit(1)
	}
	<-finished
}

func desiredAddrTypes(addrs []core.AddressInfo) []core.AddressInfo {
	if *ipv4 == false && *ipv6 == false {
		return addrs
	}

	var keep []core.AddressInfo
	for _, addr := range addrs {
		if utils.IsIPv4(addr.Address) && (*ipv4 == false) {
			continue
		} else if utils.IsIPv6(addr.Address) && (*ipv6 == false) {
			continue
		}
		keep = append(keep, addr)
	}
	return keep
}

// If the user interrupts the program, print the summary information
func signalHandler(e *amass.Enumeration) {
	quit := make(chan os.Signal, 1)

	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	// Start final output operations
	close(e.Done)
	<-finished
	os.Exit(1)
}

func writeLogsAndMessages(logs *io.PipeReader, logfile string) {
	wildcard := regexp.MustCompile("DNS wildcard")
	avg := regexp.MustCompile("Average DNS queries")

	var filePtr *os.File
	if logfile != "" {
		var err error

		filePtr, err = os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the log file: %v\n", err)
		} else {
			defer func() {
				filePtr.Sync()
				filePtr.Close()
			}()
			filePtr.Truncate(0)
			filePtr.Seek(0, 0)
		}
	}

	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(color.Error, "Error reading the Amass logs: %v\n", err)
			break
		}

		if filePtr != nil {
			fmt.Fprintln(filePtr, line)
		}
		// Remove the timestamp
		parts := strings.Split(line, " ")
		line = strings.Join(parts[1:], " ")
		// Check for Amass DNS wildcard messages
		if wildcard.FindString(line) != "" {
			fgR.Fprintln(color.Error, line)
		}
		// Check for the Amass average DNS names messages
		if avg.FindString(line) != "" {
			fgY.Fprintln(color.Error, line)
		}
	}
}

func compileDisabledSources(enum *amass.Enumeration, include, exclude []string) []string {
	var inc, disable []string

	master := enum.GetAllSourceNames()
	// Check that the include names are valid
	if len(include) > 0 {
		for _, incname := range include {
			var found bool

			for _, name := range master {
				if strings.EqualFold(name, incname) {
					found = true
					inc = append(inc, incname)
					break
				}
			}

			if !found {
				r.Fprintf(color.Error, "%s is not an available data source\n", incname)
			}
		}
	}
	// Check that the exclude names are valid
	if len(exclude) > 0 {
		for _, exclname := range exclude {
			var found bool

			for _, name := range master {
				if strings.EqualFold(name, exclname) {
					found = true
					disable = append(disable, exclname)
					break
				}
			}

			if !found {
				r.Fprintf(color.Error, "%s is not an available data source\n", exclname)
			}
		}
	}

	if len(inc) == 0 {
		return disable
	}
	// Data sources missing from the include list are disabled
	for _, name := range master {
		var found bool

		for _, incname := range inc {
			if strings.EqualFold(name, incname) {
				found = true
				break
			}
		}

		if !found {
			disable = utils.UniqueAppend(disable, name)
		}
	}
	return disable
}
