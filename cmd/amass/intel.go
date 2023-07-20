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
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/format"
	"github.com/owasp-amass/amass/v4/intel"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/config/config"
)

const (
	intelUsageMsg = "intel [options] [-whois -d DOMAIN] [-addr ADDR -asn ASN -cidr CIDR]"
)

type intelArgs struct {
	Addresses        format.ParseIPs
	ASNs             format.ParseASNs
	CIDRs            format.ParseCIDRs
	OrganizationName string
	Domains          *stringset.Set
	Excluded         *stringset.Set
	Included         *stringset.Set
	MaxDNSQueries    int
	Ports            format.ParseInts
	Resolvers        *stringset.Set
	Timeout          int
	Options          struct {
		Active       bool
		DemoMode     bool
		IPs          bool
		IPv4         bool
		IPv6         bool
		ListSources  bool
		ReverseWhois bool
		Verbose      bool
	}
	Filepaths struct {
		ConfigFile   string
		Directory    string
		Domains      format.ParseStrings
		ExcludedSrcs string
		IncludedSrcs string
		LogFile      string
		Resolvers    format.ParseStrings
		TermOut      string
	}
}

func defineIntelArgumentFlags(intelFlags *flag.FlagSet, args *intelArgs) {
	intelFlags.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	intelFlags.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	intelFlags.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	intelFlags.StringVar(&args.OrganizationName, "org", "", "Search string provided against AS description information")
	intelFlags.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	intelFlags.Var(args.Excluded, "exclude", "Data source names separated by commas to be excluded")
	intelFlags.Var(args.Included, "include", "Data source names separated by commas to be included")
	intelFlags.IntVar(&args.MaxDNSQueries, "max-dns-queries", 0, "Maximum number of concurrent DNS queries")
	intelFlags.Var(&args.Ports, "p", "Ports separated by commas (default: 80, 443)")
	intelFlags.Var(args.Resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
	intelFlags.IntVar(&args.Timeout, "timeout", 0, "Number of minutes to let enumeration run before quitting")
}

func defineIntelOptionFlags(intelFlags *flag.FlagSet, args *intelArgs) {
	intelFlags.BoolVar(&args.Options.Active, "active", false, "Attempt certificate name grabs")
	intelFlags.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	intelFlags.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	intelFlags.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	intelFlags.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	intelFlags.BoolVar(&args.Options.ListSources, "list", false, "Print additional information")
	intelFlags.BoolVar(&args.Options.ReverseWhois, "whois", false, "All provided domains are run through reverse whois")
	intelFlags.BoolVar(&args.Options.Verbose, "v", false, "Output status / debug / troubleshooting info")
}

func defineIntelFilepathFlags(intelFlags *flag.FlagSet, args *intelArgs) {
	intelFlags.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
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
	if (args.Excluded.Len() > 0 || args.Filepaths.ExcludedSrcs != "") &&
		(args.Included.Len() > 0 || args.Filepaths.IncludedSrcs != "") {
		commandUsage(intelUsageMsg, intelCommand, intelBuf)
		os.Exit(1)
	}
	if err := processIntelInputFiles(&args); err != nil {
		fmt.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}

	cfg := config.NewConfig()
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		// Check if a config file was provided that has DNS resolvers specified
		if len(cfg.Resolvers) > 0 && args.Resolvers.Len() == 0 {
			args.Resolvers = stringset.New(cfg.Resolvers...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	// Override configuration file settings with command-line arguments
	if err := cfg.UpdateConfig(args); err != nil {
		r.Fprintf(color.Error, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Some input validation
	if !args.Options.ReverseWhois && args.OrganizationName == "" && !args.Options.ListSources &&
		len(args.Addresses) == 0 && len(args.CIDRs) == 0 && len(args.ASNs) == 0 {
		commandUsage(intelUsageMsg, intelCommand, intelBuf)
		os.Exit(1)
	}
	if !cfg.Active && len(args.Ports) > 0 {
		r.Fprintln(color.Error, "Ports can only be scanned in the active mode")
		os.Exit(1)
	}

	// Check if the user requested data source information
	if args.Options.ListSources && len(args.ASNs) == 0 {
		for _, info := range GetAllSourceInfo(cfg) {
			g.Println(info)
		}
		return
	}

	rLog, wLog := io.Pipe()
	cfg.Log = log.New(wLog, "", log.Lmicroseconds)
	logfile := filepath.Join(config.OutputDirectory(cfg.Dir), "amass.log")
	if args.Filepaths.LogFile != "" {
		logfile = args.Filepaths.LogFile
	}

	createOutputDirectory(cfg)
	go writeLogsAndMessages(rLog, logfile, args.Options.Verbose)

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return
	}

	if err := sys.SetDataSources(datasrcs.GetAllSources(sys)); err != nil {
		return
	}

	if args.OrganizationName != "" {
		var asns []int
		for _, entry := range sys.Cache().DescriptionSearch(args.OrganizationName) {
			asns = append(asns, entry.ASN)
		}
		if len(asns) > 0 {
			printNetblocks(asns, cfg, sys)
		}
		return
	}
	// Check if the user requested additional ASN & netblock information
	if args.Options.ListSources && len(args.ASNs) > 0 {
		printNetblocks(args.ASNs, cfg, sys)
		return
	}

	ic := intel.NewCollection(cfg, sys)
	if ic == nil {
		r.Fprintf(color.Error, "%s\n", "No DNS resolvers passed the sanity check")
		os.Exit(1)
	}

	if args.Options.ReverseWhois {
		if len(ic.Config.Domains()) == 0 {
			r.Fprintln(color.Error, "No root domain names were provided")
			os.Exit(1)
		}

		args.Options.IPs = false
		args.Options.IPv4 = false
		args.Options.IPv6 = false
		go func() { _ = ic.ReverseWhois() }()
	} else {
		var ctx context.Context
		var cancel context.CancelFunc
		if args.Timeout == 0 {
			ctx, cancel = context.WithCancel(context.Background())
		} else {
			ctx, cancel = context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Minute)
		}
		defer cancel()
		// Monitor for cancellation by the user
		go func() {
			quit := make(chan os.Signal, 1)
			signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

			select {
			case <-quit:
				cancel()
			case <-ctx.Done():
			}
		}()

		go func() { _ = ic.HostedDomains(ctx) }()
	}

	if !processIntelOutput(ic, &args) {
		os.Exit(1)
	}
}

func printNetblocks(asns []int, cfg *config.Config, sys systems.System) {
	for _, asn := range asns {
		systems.PopulateCache(context.Background(), asn, sys)

		d := sys.Cache().ASNSearch(asn)
		if d == nil {
			continue
		}

		fmt.Printf("%s%s %s %s\n", blue("ASN: "), yellow(strconv.Itoa(asn)), green("-"), green(d.Description))
		for _, cidr := range d.Netblocks {
			fmt.Printf("%s\n", yellow(fmt.Sprintf("\t%s", cidr)))
		}
	}
}

func processIntelOutput(ic *intel.Collection, args *intelArgs) bool {
	var err error
	dir := config.OutputDirectory(ic.Config.Dir)

	txtfile := filepath.Join(dir, "amass.txt")
	if args.Filepaths.TermOut != "" {
		txtfile = args.Filepaths.TermOut
	}

	var outptr *os.File
	if txtfile != "" {
		outptr, err = os.OpenFile(txtfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the text output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			_ = outptr.Sync()
			_ = outptr.Close()
		}()
		_ = outptr.Truncate(0)
		_, _ = outptr.Seek(0, 0)
	}

	var found bool
	// Collect all the names returned by the intelligence collection
	for out := range ic.Output {
		_, ips := format.OutputLineParts(out, args.Options.IPs || args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)

		if ips != "" {
			ips = " " + ips
		}

		fmt.Fprintf(color.Output, "%s%s\n", green(out.Domain), yellow(ips))
		// Handle writing the line to a specified output file
		if outptr != nil {
			fmt.Fprintf(outptr, "%s%s\n", out.Domain, ips)
		}
		found = true
	}
	return found
}

// Obtain parameters from provided input files
func processIntelInputFiles(args *intelArgs) error {
	if args.Filepaths.ExcludedSrcs != "" {
		list, err := config.GetListFromFile(args.Filepaths.ExcludedSrcs)
		if err != nil {
			return fmt.Errorf("failed to parse the exclude file: %v", err)
		}
		args.Excluded.InsertMany(list...)
	}
	if args.Filepaths.IncludedSrcs != "" {
		list, err := config.GetListFromFile(args.Filepaths.IncludedSrcs)
		if err != nil {
			return fmt.Errorf("failed to parse the include file: %v", err)
		}
		args.Included.InsertMany(list...)
	}
	if len(args.Filepaths.Domains) > 0 {
		for _, f := range args.Filepaths.Domains {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("failed to parse the domain names file: %v", err)
			}

			args.Domains.InsertMany(list...)
		}
	}
	if len(args.Filepaths.Resolvers) > 0 {
		for _, f := range args.Filepaths.Resolvers {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("failed to parse the resolver file: %v", err)
			}

			args.Resolvers.InsertMany(list...)
		}
	}
	return nil
}

// Setup the amass intelligence collection settings
func (i intelArgs) OverrideConfig(conf *config.Config) error {
	if i.Options.Active {
		conf.Active = true
	}
	if len(i.Addresses) > 0 {
		conf.Scope.Addresses = i.Addresses
	}
	if len(i.ASNs) > 0 {
		conf.Scope.ASNs = i.ASNs
	}
	if len(i.CIDRs) > 0 {
		conf.Scope.CIDRs = i.CIDRs
	}
	if len(i.Ports) > 0 {
		conf.Scope.Ports = i.Ports
	}
	if i.Filepaths.Directory != "" {
		conf.Dir = i.Filepaths.Directory
	}
	if i.Options.Verbose {
		conf.Verbose = true
	}
	if i.Resolvers.Len() > 0 {
		conf.SetResolvers(i.Resolvers.Slice()...)
	}
	if i.MaxDNSQueries > 0 {
		conf.MaxDNSQueries = i.MaxDNSQueries
	}

	if i.Included.Len() > 0 {
		conf.SourceFilter.Include = true
		conf.SourceFilter.Sources = i.Included.Slice()
	} else if i.Excluded.Len() > 0 {
		conf.SourceFilter.Include = false
		conf.SourceFilter.Sources = i.Excluded.Slice()
	}

	// Attempt to add the provided domains to the configuration
	conf.AddDomains(i.Domains.Slice()...)
	return nil
}
