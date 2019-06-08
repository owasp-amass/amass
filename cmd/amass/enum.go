// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
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
	homedir "github.com/mitchellh/go-homedir"
)

const (
	enumUsageMsg = "enum [options] -d domain"
)

var (
	finished chan struct{}
)

type enumArgs struct {
	Addresses       utils.ParseIPs
	ASNs            utils.ParseInts
	CIDRs           utils.ParseCIDRs
	AltWordList     []string
	BruteWordList   []string
	Blacklist       utils.ParseStrings
	Domains         utils.ParseStrings
	Excluded        utils.ParseStrings
	Included        utils.ParseStrings
	MaxDNSQueries   int
	MinForRecursive int
	Names           []string
	Ports           utils.ParseInts
	Resolvers       utils.ParseStrings
	Options         struct {
		Active       bool
		BruteForcing bool
		DemoMode     bool
		IPs          bool
		IPv4         bool
		IPv6         bool
		ListSources  bool
		NoAlts       bool
		NoRecursive  bool
		Passive      bool
		Sources      bool
		Unresolved   bool
	}
	Filepaths struct {
		AllFilePrefix string
		AltWordlist   string
		Blacklist     string
		BruteWordlist string
		ConfigFile    string
		DataOpts      string
		Directory     string
		Domains       string
		ExcludedSrcs  string
		IncludedSrcs  string
		JSONOutput    string
		LogFile       string
		Names         string
		Resolvers     string
		TermOut       string
	}
}

func defineEnumArgumentFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	enumFlags.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	enumFlags.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	enumFlags.Var(&args.Blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	enumFlags.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	enumFlags.Var(&args.Excluded, "exclude", "Data source names separated by commas to be excluded")
	enumFlags.Var(&args.Included, "include", "Data source names separated by commas to be included")
	enumFlags.IntVar(&args.MaxDNSQueries, "max-dns-queries", 0, "Maximum number of concurrent DNS queries")
	enumFlags.IntVar(&args.MinForRecursive, "min-for-recursive", 0, "Number of subdomain discoveries before recursive brute forcing")
	enumFlags.Var(&args.Ports, "p", "Ports separated by commas (default: 443)")
	enumFlags.Var(&args.Resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
}

func defineEnumOptionFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.BoolVar(&args.Options.Active, "active", false, "Attempt zone transfers and certificate name grabs")
	enumFlags.BoolVar(&args.Options.BruteForcing, "brute", false, "Execute brute forcing after searches")
	enumFlags.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	enumFlags.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	enumFlags.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	enumFlags.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	enumFlags.BoolVar(&args.Options.ListSources, "list", false, "Print the names of all available data sources")
	enumFlags.BoolVar(&args.Options.NoAlts, "noalts", false, "Disable generation of altered names")
	enumFlags.BoolVar(&args.Options.NoRecursive, "norecursive", false, "Turn off recursive brute forcing")
	enumFlags.BoolVar(&args.Options.Passive, "passive", false, "Disable DNS resolution of names and dependent features")
	enumFlags.BoolVar(&args.Options.Sources, "src", false, "Print data sources for the discovered names")
	enumFlags.BoolVar(&args.Options.Unresolved, "include-unresolvable", false, "Output DNS names that did not resolve")
}

func defineEnumFilepathFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.StringVar(&args.Filepaths.AllFilePrefix, "oA", "", "Path prefix used for naming all output files")
	enumFlags.StringVar(&args.Filepaths.AltWordlist, "aw", "", "Path to a different wordlist file for alterations")
	enumFlags.StringVar(&args.Filepaths.Blacklist, "blf", "", "Path to a file providing blacklisted subdomains")
	enumFlags.StringVar(&args.Filepaths.BruteWordlist, "w", "", "Path to a different wordlist file")
	enumFlags.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	enumFlags.StringVar(&args.Filepaths.DataOpts, "do", "", "Path to data operations JSON output file")
	enumFlags.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the output files")
	enumFlags.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	enumFlags.StringVar(&args.Filepaths.ExcludedSrcs, "ef", "", "Path to a file providing data sources to exclude")
	enumFlags.StringVar(&args.Filepaths.IncludedSrcs, "if", "", "Path to a file providing data sources to include")
	enumFlags.StringVar(&args.Filepaths.JSONOutput, "json", "", "Path to the JSON output file")
	enumFlags.StringVar(&args.Filepaths.LogFile, "log", "", "Path to the log file where errors will be written")
	enumFlags.StringVar(&args.Filepaths.Names, "nf", "", "Path to a file providing already known subdomain names")
	enumFlags.StringVar(&args.Filepaths.Resolvers, "rf", "", "Path to a file providing preferred DNS resolvers")
	enumFlags.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")
}

func runEnumCommand(clArgs []string) {
	var args enumArgs
	var help1, help2 bool
	enumCommand := flag.NewFlagSet("enum", flag.ExitOnError)

	enumBuf := new(bytes.Buffer)
	enumCommand.SetOutput(enumBuf)

	enumCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	enumCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	defineEnumArgumentFlags(enumCommand, &args)
	defineEnumOptionFlags(enumCommand, &args)
	defineEnumFilepathFlags(enumCommand, &args)

	if len(clArgs) < 1 {
		commandUsage(enumUsageMsg, enumCommand, enumBuf)
		return
	}

	if err := enumCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(enumUsageMsg, enumCommand, enumBuf)
		return
	}

	// Check if the user has requested the data source names
	if args.Options.ListSources {
		enum := amass.NewEnumeration()

		for _, name := range enum.GetAllSourceNames() {
			g.Println(name)
		}
		return
	}
	// Some input validation
	if args.Options.Passive && (args.Options.IPs || args.Options.IPv4 || args.Options.IPv6) {
		r.Fprintln(color.Error, "IP addresses cannot be provided without DNS resolution")
		os.Exit(1)
	}
	if args.Options.Passive && args.Options.BruteForcing {
		r.Fprintln(color.Error, "Brute forcing cannot be performed without DNS resolution")
		os.Exit(1)
	}

	if err := processEnumInputFiles(&args); err != nil {
		fmt.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	rLog, wLog := io.Pipe()
	enum := amass.NewEnumeration()
	enum.Config.Log = log.New(wLog, "", log.Lmicroseconds)
	// Check if a configuration file was provided, and if so, load the settings
	acquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, enum.Config)
	// Override configuration file settings with command-line arguments
	if err := updateEnumConfiguration(enum, &args); err != nil {
		r.Fprintf(color.Error, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	if len(args.Resolvers) > 0 {
		core.SetCustomResolvers(args.Resolvers)
	}

	processEnumOutput(enum, &args, rLog)
}

func processEnumOutput(enum *amass.Enumeration, args *enumArgs, pipe *io.PipeReader) {
	var err error

	// Prepare output file paths
	dir := enum.Config.Dir
	if dir == "" {
		path, err := homedir.Dir()
		if err != nil {
			r.Fprintln(color.Error, "Failed to obtain the user home directory")
			os.Exit(1)
		}
		dir = filepath.Join(path, handlers.DefaultGraphDBDirectory)
	}
	// If the directory does not yet exist, create it
	if err = os.MkdirAll(dir, 0755); err != nil {
		r.Fprintf(color.Error, "Failed to create the directory: %v\n", err)
		os.Exit(1)
	}
	logfile := filepath.Join(dir, "amass.log")
	if args.Filepaths.LogFile != "" {
		logfile = args.Filepaths.LogFile
	}
	txtfile := filepath.Join(dir, "amass.txt")
	if args.Filepaths.TermOut != "" {
		txtfile = args.Filepaths.TermOut
	}
	jsonfile := filepath.Join(dir, "amass.json")
	if args.Filepaths.JSONOutput != "" {
		jsonfile = args.Filepaths.JSONOutput
	}
	datafile := filepath.Join(dir, "amass_data.json")
	if args.Filepaths.DataOpts != "" {
		datafile = args.Filepaths.DataOpts
	}
	if args.Filepaths.AllFilePrefix != "" {
		logfile = args.Filepaths.AllFilePrefix + ".log"
		txtfile = args.Filepaths.AllFilePrefix + ".txt"
		jsonfile = args.Filepaths.AllFilePrefix + ".json"
		datafile = args.Filepaths.AllFilePrefix + "_data.json"
	}

	go writeLogsAndMessages(pipe, logfile)
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
			out.Addresses = amass.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
			if !enum.Config.Passive && len(out.Addresses) <= 0 {
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
			// Handle writing the line to a specified output file
			if outptr != nil {
				fmt.Fprintf(outptr, "%s%s%s\n", source, name, ips)
			}
			// Handle encoding the result as JSON
			if jsonptr != nil {
				enc.Encode(out)
			}
		}
		if total == 0 {
			r.Println("No names were discovered")
		} else {
			amass.PrintEnumerationSummary(total, tags, asns, args.Options.DemoMode)
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

// Obtain parameters from provided input files
func processEnumInputFiles(args *enumArgs) error {
	var err error

	if args.Options.BruteForcing && args.Filepaths.BruteWordlist != "" {
		args.BruteWordList, err = core.GetListFromFile(args.Filepaths.BruteWordlist)
		if err != nil {
			return fmt.Errorf("Failed to parse the brute force wordlist file: %v", err)
		}
	}
	if !args.Options.NoAlts && args.Filepaths.AltWordlist != "" {
		args.AltWordList, err = core.GetListFromFile(args.Filepaths.AltWordlist)
		if err != nil {
			return fmt.Errorf("Failed to parse the alterations wordlist file: %v", err)
		}
	}
	if args.Filepaths.Blacklist != "" {
		list, err := core.GetListFromFile(args.Filepaths.Blacklist)
		if err != nil {
			return fmt.Errorf("Failed to parse the blacklist file: %v", err)
		}
		args.Blacklist = utils.UniqueAppend(args.Blacklist, list...)
	}
	if args.Filepaths.ExcludedSrcs != "" {
		list, err := core.GetListFromFile(args.Filepaths.ExcludedSrcs)
		if err != nil {
			return fmt.Errorf("Failed to parse the exclude file: %v", err)
		}
		args.Excluded = utils.UniqueAppend(args.Excluded, list...)
	}
	if args.Filepaths.IncludedSrcs != "" {
		list, err := core.GetListFromFile(args.Filepaths.IncludedSrcs)
		if err != nil {
			return fmt.Errorf("Failed to parse the include file: %v", err)
		}
		args.Included = utils.UniqueAppend(args.Included, list...)
	}
	if args.Filepaths.Names != "" {
		list, err := core.GetListFromFile(args.Filepaths.Names)
		if err != nil {
			return fmt.Errorf("Failed to parse the subdomain names file: %v", err)
		}
		args.Names = utils.UniqueAppend(args.Names, list...)
	}
	if args.Filepaths.Domains != "" {
		list, err := core.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			return fmt.Errorf("Failed to parse the domain names file: %v", err)
		}
		args.Domains = utils.UniqueAppend(args.Domains, list...)
	}
	if args.Filepaths.Resolvers != "" {
		list, err := core.GetListFromFile(args.Filepaths.Resolvers)
		if err != nil {
			return fmt.Errorf("Failed to parse the resolver file: %v", err)
		}
		args.Resolvers = utils.UniqueAppend(args.Resolvers, list...)
	}
	// Check if a config file was provided that has DNS resolvers specified
	if args.Filepaths.ConfigFile != "" {
		if r, err := core.GetResolversFromSettings(args.Filepaths.ConfigFile); err == nil {
			args.Resolvers = utils.UniqueAppend(args.Resolvers, r...)
		}
	}
	return nil
}

// Setup the amass enumeration settings
func updateEnumConfiguration(enum *amass.Enumeration, args *enumArgs) error {
	if len(args.Addresses) > 0 {
		enum.Config.Addresses = args.Addresses
	}
	if len(args.ASNs) > 0 {
		enum.Config.ASNs = args.ASNs
	}
	if len(args.CIDRs) > 0 {
		enum.Config.CIDRs = args.CIDRs
	}
	if len(args.Ports) > 0 {
		enum.Config.Ports = args.Ports
	}
	if args.Filepaths.Directory != "" {
		enum.Config.Dir = args.Filepaths.Directory
	}
	if args.MaxDNSQueries > 0 {
		enum.Config.MaxDNSQueries = args.MaxDNSQueries
	}
	if len(args.BruteWordList) > 0 {
		enum.Config.Wordlist = args.BruteWordList
	}
	if len(args.AltWordList) > 0 {
		enum.Config.AltWordlist = args.AltWordList
	}
	if len(args.Names) > 0 {
		enum.ProvidedNames = args.Names
	}
	if args.Options.BruteForcing {
		enum.Config.BruteForcing = true
	}
	if args.Options.NoAlts {
		enum.Config.Alterations = false
	}
	if args.Options.NoRecursive {
		enum.Config.Recursive = false
	}
	if args.MinForRecursive > 0 {
		enum.Config.MinForRecursive = args.MinForRecursive
	}
	if args.Options.Active {
		enum.Config.Active = true
	}
	if args.Options.Unresolved {
		enum.Config.IncludeUnresolvable = true
	}
	if args.Options.Passive {
		enum.Config.Passive = true
	}
	if len(args.Blacklist) > 0 {
		enum.Config.Blacklist = args.Blacklist
	}

	disabled := compileDisabledSources(enum.GetAllSourceNames(), args.Included, args.Excluded)
	if len(disabled) > 0 {
		enum.Config.DisabledDataSources = disabled
	}

	// Attempt to add the provided domains to the configuration
	enum.Config.AddDomains(args.Domains)
	if len(enum.Config.Domains()) == 0 {
		return errors.New("No root domain names were provided")
	}
	return nil
}

func compileDisabledSources(srcs []string, include, exclude []string) []string {
	var inc, disable []string

	master := srcs
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
