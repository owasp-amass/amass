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

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/enum"
	"github.com/OWASP/Amass/stringset"
	"github.com/OWASP/Amass/utils"
	"github.com/fatih/color"
	homedir "github.com/mitchellh/go-homedir"
)

const (
	enumUsageMsg = "enum [options] -d DOMAIN"
)

var (
	finished chan struct{}
)

type enumArgs struct {
	Addresses         utils.ParseIPs
	ASNs              utils.ParseInts
	CIDRs             utils.ParseCIDRs
	AltWordList       stringset.Set
	AltWordListMask   stringset.Set
	BruteWordList     stringset.Set
	BruteWordListMask stringset.Set
	Blacklist         stringset.Set
	Domains           stringset.Set
	Excluded          stringset.Set
	Included          stringset.Set
	MaxDNSQueries     int
	MinForRecursive   int
	Names             stringset.Set
	Ports             utils.ParseInts
	Resolvers         stringset.Set
	Options           struct {
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
		AltWordlist   utils.ParseStrings
		Blacklist     string
		BruteWordlist utils.ParseStrings
		ConfigFile    string
		DataOpts      string
		Directory     string
		Domains       utils.ParseStrings
		ExcludedSrcs  string
		IncludedSrcs  string
		JSONOutput    string
		LogFile       string
		Names         utils.ParseStrings
		Resolvers     utils.ParseStrings
		TermOut       string
	}
}

func defineEnumArgumentFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	enumFlags.Var(&args.AltWordListMask, "awm", "\"hashcat-style\" wordlist masks for name alterations")
	enumFlags.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	enumFlags.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	enumFlags.Var(&args.Blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	enumFlags.Var(&args.BruteWordListMask, "wm", "\"hashcat-style\" wordlist masks for DNS brute forcing")
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
	enumFlags.Var(&args.Filepaths.AltWordlist, "aw", "Path to a different wordlist file for alterations")
	enumFlags.StringVar(&args.Filepaths.Blacklist, "blf", "", "Path to a file providing blacklisted subdomains")
	enumFlags.Var(&args.Filepaths.BruteWordlist, "w", "Path to a different wordlist file")
	enumFlags.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	enumFlags.StringVar(&args.Filepaths.DataOpts, "do", "", "Path to data operations JSON output file")
	enumFlags.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the output files")
	enumFlags.Var(&args.Filepaths.Domains, "df", "Path to a file providing root domain names")
	enumFlags.StringVar(&args.Filepaths.ExcludedSrcs, "ef", "", "Path to a file providing data sources to exclude")
	enumFlags.StringVar(&args.Filepaths.IncludedSrcs, "if", "", "Path to a file providing data sources to include")
	enumFlags.StringVar(&args.Filepaths.JSONOutput, "json", "", "Path to the JSON output file")
	enumFlags.StringVar(&args.Filepaths.LogFile, "log", "", "Path to the log file where errors will be written")
	enumFlags.Var(&args.Filepaths.Names, "nf", "Path to a file providing already known subdomain names (from other tools/sources)")
	enumFlags.Var(&args.Filepaths.Resolvers, "rf", "Path to a file providing preferred DNS resolvers")
	enumFlags.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")
}

func runEnumCommand(clArgs []string) {
	args := enumArgs{
		AltWordList:       stringset.New(),
		AltWordListMask:   stringset.New(),
		BruteWordList:     stringset.New(),
		BruteWordListMask: stringset.New(),
		Blacklist:         stringset.New(),
		Domains:           stringset.New(),
		Excluded:          stringset.New(),
		Included:          stringset.New(),
		Names:             stringset.New(),
		Resolvers:         stringset.New(),
	}
	var help1, help2 bool
	enumCommand := flag.NewFlagSet("enum", flag.ContinueOnError)

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
		for _, name := range GetAllSourceNames() {
			g.Println(name)
		}
		return
	}

	if len(args.AltWordListMask) > 0 {
		args.AltWordList.Union(args.AltWordListMask)
	}
	if len(args.BruteWordListMask) > 0 {
		args.BruteWordList.Union(args.BruteWordListMask)
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

	e := enum.NewEnumeration()
	if e == nil {
		r.Fprintf(color.Error, "%s\n", "No DNS resolvers passed the sanity check")
		os.Exit(1)
	}

	rLog, wLog := io.Pipe()
	e.Config.Log = log.New(wLog, "", log.Lmicroseconds)

	// Check if a configuration file was provided, and if so, load the settings
	if f, err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, e.Config); err == nil {
		// Check if a config file was provided that has DNS resolvers specified
		if r, err := config.GetResolversFromSettings(f); err == nil && len(args.Resolvers) == 0 {
			args.Resolvers = stringset.New(r...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	// Override configuration file settings with command-line arguments
	if err := updateEnumConfiguration(e, &args); err != nil {
		r.Fprintf(color.Error, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	if len(args.Resolvers) > 0 {
		if err := e.Pool.SetResolvers(args.Resolvers.ToSlice()); err != nil {
			r.Fprintf(color.Error, "Failed to set custom DNS resolvers: %v\n", err)
			os.Exit(1)
		}
	}

	processEnumOutput(e, &args, rLog)
}

func processEnumOutput(e *enum.Enumeration, args *enumArgs, pipe *io.PipeReader) {
	var err error

	// Prepare output file paths
	dir := e.Config.Dir
	if dir == "" {
		path, err := homedir.Dir()
		if err != nil {
			r.Fprintln(color.Error, "Failed to obtain the user home directory")
			os.Exit(1)
		}
		dir = filepath.Join(path, config.DefaultOutputDirectory)
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
	if !e.Config.Passive && datafile != "" {
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
		e.Config.DataOptsWriter = fileptr
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
		asns := make(map[int]*utils.ASNSummaryData)
		// Collect all the names returned by the enumeration
		for out := range e.Output {
			out.Addresses = utils.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
			if !e.Config.Passive && len(out.Addresses) <= 0 {
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
			utils.PrintEnumerationSummary(total, tags, asns, args.Options.DemoMode)
		}
		close(finished)
	}()
	// Start the enumeration process
	go signalHandler(e)
	if err := e.Start(); err != nil {
		r.Println(err)
		os.Exit(1)
	}
	<-finished
}

// If the user interrupts the program, print the summary information
func signalHandler(e *enum.Enumeration) {
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
	if args.Options.BruteForcing && len(args.Filepaths.BruteWordlist) > 0 {
		for _, f := range args.Filepaths.BruteWordlist {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the brute force wordlist file: %v", err)
			}

			args.BruteWordList.InsertMany(list...)
		}
	}
	if !args.Options.NoAlts && len(args.Filepaths.AltWordlist) > 0 {
		for _, f := range args.Filepaths.AltWordlist {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the alterations wordlist file: %v", err)
			}

			args.AltWordList.InsertMany(list...)
		}
	}
	if args.Filepaths.Blacklist != "" {
		list, err := config.GetListFromFile(args.Filepaths.Blacklist)
		if err != nil {
			return fmt.Errorf("Failed to parse the blacklist file: %v", err)
		}
		args.Blacklist.InsertMany(list...)
	}
	if args.Filepaths.ExcludedSrcs != "" {
		list, err := config.GetListFromFile(args.Filepaths.ExcludedSrcs)
		if err != nil {
			return fmt.Errorf("Failed to parse the exclude file: %v", err)
		}
		args.Excluded.InsertMany(list...)
	}
	if args.Filepaths.IncludedSrcs != "" {
		list, err := config.GetListFromFile(args.Filepaths.IncludedSrcs)
		if err != nil {
			return fmt.Errorf("Failed to parse the include file: %v", err)
		}
		args.Included.InsertMany(list...)
	}
	if len(args.Filepaths.Names) > 0 {
		for _, f := range args.Filepaths.Names {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the subdomain names file: %v", err)
			}

			args.Names.InsertMany(list...)
		}
	}
	if len(args.Filepaths.Domains) > 0 {
		for _, f := range args.Filepaths.Domains {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the domain names file: %v", err)
			}

			args.Domains.InsertMany(list...)
		}
	}
	if len(args.Filepaths.Resolvers) > 0 {
		for _, f := range args.Filepaths.Resolvers {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the resolver file: %v", err)
			}

			args.Resolvers.InsertMany(list...)
		}
	}
	return nil
}

// Setup the amass enumeration settings
func updateEnumConfiguration(e *enum.Enumeration, args *enumArgs) error {
	if len(args.Addresses) > 0 {
		e.Config.Addresses = args.Addresses
	}
	if len(args.ASNs) > 0 {
		e.Config.ASNs = args.ASNs
	}
	if len(args.CIDRs) > 0 {
		e.Config.CIDRs = args.CIDRs
	}
	if len(args.Ports) > 0 {
		e.Config.Ports = args.Ports
	}
	if args.Filepaths.Directory != "" {
		e.Config.Dir = args.Filepaths.Directory
	}
	if args.MaxDNSQueries > 0 {
		e.Config.MaxDNSQueries = args.MaxDNSQueries
	}
	if len(args.BruteWordList) > 0 {
		e.Config.Wordlist = args.BruteWordList
	}
	if len(args.AltWordList) > 0 {
		e.Config.AltWordlist = args.AltWordList
	}
	if len(args.Names) > 0 {
		e.ProvidedNames = args.Names.ToSlice()
	}
	if args.Options.BruteForcing {
		e.Config.BruteForcing = true
	}
	if args.Options.NoAlts {
		e.Config.Alterations = false
	}
	if args.Options.NoRecursive {
		e.Config.Recursive = false
	}
	if args.MinForRecursive > 0 {
		e.Config.MinForRecursive = args.MinForRecursive
	}
	if args.Options.Active {
		e.Config.Active = true
	}
	if args.Options.Unresolved {
		e.Config.IncludeUnresolvable = true
	}
	if args.Options.Passive {
		e.Config.Passive = true
	}
	if len(args.Blacklist) > 0 {
		e.Config.Blacklist = args.Blacklist
	}

	disabled := compileDisabledSources(e.GetAllSourceNames(), args.Included, args.Excluded)
	if len(disabled) > 0 {
		e.Config.DisabledDataSources = disabled
	}

	// Attempt to add the provided domains to the configuration
	e.Config.AddDomains(args.Domains.ToSlice())
	if len(e.Config.Domains()) == 0 {
		return errors.New("No root domain names were provided")
	}
	return nil
}

func compileDisabledSources(srcs []string, include, exclude stringset.Set) stringset.Set {
	// Check that the include names are valid
	master := stringset.New(srcs...)
	disable := stringset.New(srcs...)

	// Remove explicitly include sources
	disable.Subtract(include)

	// Add back in explicitly excluded sources
	disable.Union(exclude)

	// Make sure we dont have any outside of the master list
	disable.Intersect(master)

	return disable
}
