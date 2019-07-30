// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/intel"
	"github.com/OWASP/Amass/stringset"
	"github.com/OWASP/Amass/utils"
	"github.com/fatih/color"
	homedir "github.com/mitchellh/go-homedir"
)

const (
	intelUsageMsg = "intel [options] [-whois -d DOMAIN] [-addr ADDR -asn ASN -cidr CIDR]"
)

type intelArgs struct {
	Addresses        utils.ParseIPs
	ASNs             utils.ParseInts
	CIDRs            utils.ParseCIDRs
	OrganizationName string
	Domains          stringset.Set
	Excluded         stringset.Set
	Included         stringset.Set
	MaxDNSQueries    int
	Ports            utils.ParseInts
	Resolvers        stringset.Set
	Options          struct {
		Active       bool
		DemoMode     bool
		IPs          bool
		IPv4         bool
		IPv6         bool
		ListSources  bool
		ReverseWhois bool
		Sources      bool
	}
	Filepaths struct {
		ConfigFile   string
		Directory    string
		Domains      utils.ParseStrings
		ExcludedSrcs string
		IncludedSrcs string
		LogFile      string
		Resolvers    utils.ParseStrings
		TermOut      string
	}
}

func defineIntelArgumentFlags(intelFlags *flag.FlagSet, args *intelArgs) {
	intelFlags.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	intelFlags.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	intelFlags.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	intelFlags.StringVar(&args.OrganizationName, "org", "", "Search string provided against AS description information")
	intelFlags.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	intelFlags.Var(&args.Excluded, "exclude", "Data source names separated by commas to be excluded")
	intelFlags.Var(&args.Included, "include", "Data source names separated by commas to be included")
	intelFlags.IntVar(&args.MaxDNSQueries, "max-dns-queries", 0, "Maximum number of concurrent DNS queries")
	intelFlags.Var(&args.Ports, "p", "Ports separated by commas (default: 443)")
	intelFlags.Var(&args.Resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
}

func defineIntelOptionFlags(intelFlags *flag.FlagSet, args *intelArgs) {
	intelFlags.BoolVar(&args.Options.Active, "active", false, "Attempt zone transfers and certificate name grabs")
	intelFlags.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	intelFlags.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	intelFlags.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	intelFlags.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	intelFlags.BoolVar(&args.Options.ListSources, "list", false, "Print the names of all available data sources")
	intelFlags.BoolVar(&args.Options.ReverseWhois, "whois", false, "All discovered domains are run through reverse whois")
	intelFlags.BoolVar(&args.Options.Sources, "src", false, "Print data sources for the discovered names")
}

func defineIntelFilepathFlags(intelFlags *flag.FlagSet, args *intelArgs) {
	intelFlags.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	intelFlags.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the output files")
	intelFlags.Var(&args.Filepaths.Domains, "df", "Path to a file providing root domain names")
	intelFlags.StringVar(&args.Filepaths.ExcludedSrcs, "ef", "", "Path to a file providing data sources to exclude")
	intelFlags.StringVar(&args.Filepaths.IncludedSrcs, "if", "", "Path to a file providing data sources to include")
	intelFlags.StringVar(&args.Filepaths.LogFile, "log", "", "Path to the log file where errors will be written")
	intelFlags.Var(&args.Filepaths.Resolvers, "rf", "Path to a file providing preferred DNS resolvers")
	intelFlags.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")
}

func runIntelCommand(clArgs []string) {
	args := intelArgs{
		Domains:   stringset.New(),
		Excluded:  stringset.New(),
		Included:  stringset.New(),
		Resolvers: stringset.New(),
	}
	var help1, help2 bool
	intelCommand := flag.NewFlagSet("intel", flag.ContinueOnError)

	intelBuf := new(bytes.Buffer)
	intelCommand.SetOutput(intelBuf)

	intelCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	intelCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	defineIntelArgumentFlags(intelCommand, &args)
	defineIntelOptionFlags(intelCommand, &args)
	defineIntelFilepathFlags(intelCommand, &args)

	if len(clArgs) < 1 {
		commandUsage(intelUsageMsg, intelCommand, intelBuf)
		return
	}

	if err := intelCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(intelUsageMsg, intelCommand, intelBuf)
		return
	}

	// Check if the user has requested the data source names
	if args.Options.ListSources {
		for _, name := range GetAllSourceNames() {
			g.Println(name)
		}
		return
	}

	// Some input validation
	if !args.Options.ReverseWhois && args.OrganizationName == "" &&
		len(args.Addresses) == 0 && len(args.CIDRs) == 0 && len(args.ASNs) == 0 {
		commandUsage(intelUsageMsg, intelCommand, intelBuf)
		os.Exit(1)
	}

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	if args.OrganizationName != "" {
		records, err := intel.LookupASNsByName(args.OrganizationName)
		if err == nil {
			for _, a := range records {
				fmt.Printf("%d, %s\n", a.ASN, a.Description)
			}
		} else {
			fmt.Printf("%v\n", err)
		}
		return
	}

	if err := processIntelInputFiles(&args); err != nil {
		fmt.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}

	ic := intel.NewCollection()
	if ic == nil {
		r.Fprintf(color.Error, "%s\n", "No DNS resolvers passed the sanity check")
		os.Exit(1)
	}

	rLog, wLog := io.Pipe()
	ic.Config.Log = log.New(wLog, "", log.Lmicroseconds)

	// Check if a configuration file was provided, and if so, load the settings
	if f, err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, ic.Config); err == nil {
		// Check if a config file was provided that has DNS resolvers specified
		if r, err := config.GetResolversFromSettings(f); err == nil && len(args.Resolvers) == 0 {
			args.Resolvers = stringset.New(r...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	// Override configuration file settings with command-line arguments
	if err := updateIntelConfiguration(ic, &args); err != nil {
		r.Fprintf(color.Error, "Configuration file error: %v\n", err)
		os.Exit(1)
	}

	if len(args.Resolvers) > 0 {
		if err := ic.Pool.SetResolvers(args.Resolvers.ToSlice()); err != nil {
			r.Fprintf(color.Error, "Failed to set custom DNS resolvers: %v\n", err)
			os.Exit(1)
		}
	}

	if args.Options.ReverseWhois {
		if len(ic.Config.Domains()) == 0 {
			r.Fprintln(color.Error, "No root domain names were provided")
			os.Exit(1)
		}

		args.Options.IPs = false
		args.Options.IPv4 = false
		args.Options.IPv6 = false
		go ic.ReverseWhois()
	} else {
		go ic.HostedDomains()
	}

	go intelSignalHandler(ic)
	processIntelOutput(ic, &args, rLog)
}

func processIntelOutput(ic *intel.Collection, args *intelArgs, pipe *io.PipeReader) {
	var err error

	// Prepare output file paths
	dir := ic.Config.Dir
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

	go writeLogsAndMessages(pipe, logfile)

	var outptr *os.File
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

	// Collect all the names returned by the intelligence collection
	for out := range ic.Output {
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
	}
}

// If the user interrupts the program, print the summary information
func intelSignalHandler(ic *intel.Collection) {
	quit := make(chan os.Signal, 1)

	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	close(ic.Done)
}

func writeIntelLogsAndMessages(logs *io.PipeReader, logfile string) {
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
	}
}

// Obtain parameters from provided input files
func processIntelInputFiles(args *intelArgs) error {
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

// Setup the amass intelligence collection settings
func updateIntelConfiguration(ic *intel.Collection, args *intelArgs) error {
	if args.Options.Active {
		ic.Config.Active = true
	}
	if len(args.Addresses) > 0 {
		ic.Config.Addresses = args.Addresses
	}
	if len(args.ASNs) > 0 {
		ic.Config.ASNs = args.ASNs
	}
	if len(args.CIDRs) > 0 {
		ic.Config.CIDRs = args.CIDRs
	}
	if len(args.Ports) > 0 {
		ic.Config.Ports = args.Ports
	}
	if args.Filepaths.Directory != "" {
		ic.Config.Dir = args.Filepaths.Directory
	}
	if args.MaxDNSQueries > 0 {
		ic.Config.MaxDNSQueries = args.MaxDNSQueries
	}

	disabled := compileDisabledSources(GetAllSourceNames(), args.Included, args.Excluded)
	if len(disabled) > 0 {
		ic.Config.DisabledDataSources = disabled
	}
	// Attempt to add the provided domains to the configuration
	ic.Config.AddDomains(args.Domains.ToSlice())
	return nil
}
