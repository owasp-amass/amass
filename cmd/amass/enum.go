// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/caffix/stringset"
	pb "github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/format"
	"github.com/owasp-amass/amass/v4/resources"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/api/graphql/client"
)

const enumUsageMsg = "enum [options] -d DOMAIN"

type enumArgs struct {
	Addresses         format.ParseIPs
	ASNs              format.ParseInts
	CIDRs             format.ParseCIDRs
	AltWordList       *stringset.Set
	AltWordListMask   *stringset.Set
	BruteWordList     *stringset.Set
	BruteWordListMask *stringset.Set
	Blacklist         *stringset.Set
	Domains           *stringset.Set
	Excluded          *stringset.Set
	Included          *stringset.Set
	Interface         string
	MaxDNSQueries     int
	ResolverQPS       int
	TrustedQPS        int
	MaxDepth          int
	MinForRecursive   int
	Names             *stringset.Set
	Ports             format.ParseInts
	Resolvers         *stringset.Set
	Trusted           *stringset.Set
	Timeout           int
	Options           struct {
		Active       bool
		Alterations  bool
		BruteForcing bool
		DemoMode     bool
		ListSources  bool
		NoAlts       bool
		NoColor      bool
		NoRecursive  bool
		Passive      bool
		Silent       bool
		Verbose      bool
	}
	Filepaths struct {
		AllFilePrefix    string
		AltWordlist      format.ParseStrings
		Blacklist        string
		BruteWordlist    format.ParseStrings
		ConfigFile       string
		Directory        string
		Domains          format.ParseStrings
		ExcludedSrcs     string
		IncludedSrcs     string
		JSONOutput       string
		LogFile          string
		Names            format.ParseStrings
		Resolvers        format.ParseStrings
		Trusted          format.ParseStrings
		ScriptsDirectory string
		TermOut          string
	}
}

func defineEnumArgumentFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	enumFlags.Var(args.AltWordListMask, "awm", "\"hashcat-style\" wordlist masks for name alterations")
	enumFlags.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	enumFlags.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	enumFlags.Var(args.Blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	enumFlags.Var(args.BruteWordListMask, "wm", "\"hashcat-style\" wordlist masks for DNS brute forcing")
	enumFlags.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	enumFlags.Var(args.Excluded, "exclude", "Data source names separated by commas to be excluded")
	enumFlags.Var(args.Included, "include", "Data source names separated by commas to be included")
	enumFlags.StringVar(&args.Interface, "iface", "", "Provide the network interface to send traffic through")
	enumFlags.IntVar(&args.MaxDNSQueries, "max-dns-queries", 0, "Deprecated flag to be replaced by dns-qps in version 4.0")
	enumFlags.IntVar(&args.MaxDNSQueries, "dns-qps", 0, "Maximum number of DNS queries per second across all resolvers")
	enumFlags.IntVar(&args.ResolverQPS, "rqps", 0, "Maximum number of DNS queries per second for each untrusted resolver")
	enumFlags.IntVar(&args.TrustedQPS, "trqps", 0, "Maximum number of DNS queries per second for each trusted resolver")
	enumFlags.IntVar(&args.MaxDepth, "max-depth", 0, "Maximum number of subdomain labels for brute forcing")
	enumFlags.IntVar(&args.MinForRecursive, "min-for-recursive", 1, "Subdomain labels seen before recursive brute forcing (Default: 1)")
	enumFlags.Var(&args.Ports, "p", "Ports separated by commas (default: 80, 443)")
	enumFlags.Var(args.Resolvers, "r", "IP addresses of untrusted DNS resolvers (can be used multiple times)")
	enumFlags.Var(args.Resolvers, "tr", "IP addresses of trusted DNS resolvers (can be used multiple times)")
	enumFlags.IntVar(&args.Timeout, "timeout", 0, "Number of minutes to let enumeration run before quitting")
}

func defineEnumOptionFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.BoolVar(&args.Options.Active, "active", false, "Attempt zone transfers and certificate name grabs")
	enumFlags.BoolVar(&args.Options.BruteForcing, "brute", false, "Execute brute forcing after searches")
	enumFlags.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	enumFlags.BoolVar(&args.Options.ListSources, "list", false, "Print the names of all available data sources")
	enumFlags.BoolVar(&args.Options.Alterations, "alts", false, "Enable generation of altered names")
	enumFlags.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	enumFlags.BoolVar(&args.Options.NoRecursive, "norecursive", false, "Turn off recursive brute forcing")
	enumFlags.BoolVar(&args.Options.Passive, "passive", false, "Deprecated since passive is the default setting")
	enumFlags.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	enumFlags.BoolVar(&args.Options.Verbose, "v", false, "Output status / debug / troubleshooting info")
}

func defineEnumFilepathFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.StringVar(&args.Filepaths.AllFilePrefix, "oA", "", "Path prefix used for naming all output files")
	enumFlags.Var(&args.Filepaths.AltWordlist, "aw", "Path to a different wordlist file for alterations")
	enumFlags.StringVar(&args.Filepaths.Blacklist, "blf", "", "Path to a file providing blacklisted subdomains")
	enumFlags.Var(&args.Filepaths.BruteWordlist, "w", "Path to a different wordlist file for brute forcing")
	enumFlags.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
	enumFlags.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the output files")
	enumFlags.Var(&args.Filepaths.Domains, "df", "Path to a file providing root domain names")
	enumFlags.StringVar(&args.Filepaths.ExcludedSrcs, "ef", "", "Path to a file providing data sources to exclude")
	enumFlags.StringVar(&args.Filepaths.IncludedSrcs, "if", "", "Path to a file providing data sources to include")
	enumFlags.StringVar(&args.Filepaths.LogFile, "log", "", "Path to the log file where errors will be written")
	enumFlags.Var(&args.Filepaths.Names, "nf", "Path to a file providing already known subdomain names (from other tools/sources)")
	enumFlags.Var(&args.Filepaths.Resolvers, "rf", "Path to a file providing untrusted DNS resolvers")
	enumFlags.Var(&args.Filepaths.Trusted, "trf", "Path to a file providing trusted DNS resolvers")
	enumFlags.StringVar(&args.Filepaths.ScriptsDirectory, "scripts", "", "Path to a directory containing ADS scripts")
	enumFlags.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")
}

func runEnumCommand(clArgs []string) {
	// Extract the correct config from the user provided arguments and/or configuration file
	cfg, args := argsAndConfig(clArgs)
	if cfg == nil {
		return
	}
	createOutputDirectory(cfg)

	dir := config.OutputDirectory(cfg.Dir)
	l := selectLogger(dir, args.Filepaths.LogFile)
	// Create the client that will provide a connection to the engine
	url := "http://localhost:4000/graphql"
	if cfg.EngineAPI != nil && cfg.EngineAPI.URL != "" {
		url = cfg.EngineAPI.URL
	}

	client := client.NewClient(url)
	token, err := createSession(url, client, cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.TerminateSession(token)

	// Create interrupt channel and subscribe to server log messages
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	messages, err := client.Subscribe(token)
	if err != nil {
		fmt.Println(err)
		return
	}

	var count int
	for _, a := range makeAssets(cfg) {
		if err := client.CreateAsset(*a, token); err == nil {
			count++
		}
	}

	done := make(chan struct{})
	progress := pb.Start64(int64(count))
	go func() {
		var finished int
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-t.C:
				if stats, err := client.SessionStats(token); err == nil {
					progress.SetTotal(int64(stats.WorkItemsTotal))
					progress.SetCurrent(int64(stats.WorkItemsCompleted))
					if stats.WorkItemsCompleted == stats.WorkItemsTotal {
						finished++
						if finished == 5 {
							close(done)
							return
						}
					} else {
						finished = 0
					}
				}
			case message := <-messages:
				writeLogMessage(l, message)
			case <-done:
				return
			}
		}
	}()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-interrupt:
			close(done)
		}
	}
	progress.Finish()
}

func writeLogMessage(l *slog.Logger, message string) {
	logstr := channelJSONLog(message)
	if logstr == "" {
		return
	}

	record, err := format.JSONLogToRecord(logstr)
	if err != nil {
		return
	}

	ctx := context.Background()
	if l.Handler().Enabled(ctx, record.Level) {
		l.Handler().Handle(ctx, record)
	}
}

func channelJSONLog(data string) string {
	j := make(map[string]interface{})
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return ""
	}

	var logstr string
	// check that this is a log message sent over the sub channel
	if p, found := j["payload"]; !found {
		return ""
	} else if pmap, ok := p.(map[string]interface{}); !ok {
		return ""
	} else if d, found := pmap["data"]; !found {
		return ""
	} else if dmap, ok := d.(map[string]interface{}); !ok {
		return ""
	} else if lm, found := dmap["logMessages"]; !found {
		return ""
	} else if lmstr, ok := lm.(string); ok {
		logstr = lmstr
	}
	return logstr
}

func argsAndConfig(clArgs []string) (*config.Config, *enumArgs) {
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
		Trusted:           stringset.New(),
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
		return nil, &args
	}
	if err := enumCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(enumUsageMsg, enumCommand, enumBuf)
		return nil, &args
	}
	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = io.Discard
		color.Error = io.Discard
	}
	if args.AltWordListMask.Len() > 0 {
		args.AltWordList.Union(args.AltWordListMask)
	}
	if args.BruteWordListMask.Len() > 0 {
		args.BruteWordList.Union(args.BruteWordListMask)
	}
	if (args.Excluded.Len() > 0 || args.Filepaths.ExcludedSrcs != "") &&
		(args.Included.Len() > 0 || args.Filepaths.IncludedSrcs != "") {
		r.Fprintln(color.Error, "Cannot provide both include and exclude arguments")
		commandUsage(enumUsageMsg, enumCommand, enumBuf)
		os.Exit(1)
	}
	if err := processEnumInputFiles(&args); err != nil {
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
	if !cfg.Active && len(args.Ports) > 0 {
		r.Fprintln(color.Error, "Ports can only be scanned in the active mode")
		os.Exit(1)
	}
	if len(cfg.Domains()) == 0 {
		r.Fprintln(color.Error, "Configuration error: No root domain names were provided")
		os.Exit(1)
	}
	return cfg, &args
}

// Obtain parameters from provided input files
func processEnumInputFiles(args *enumArgs) error {
	getList := func(fp []string, name string, s *stringset.Set) error {
		for _, p := range fp {
			if p != "" {
				list, err := config.GetListFromFile(p)
				if err != nil {
					return fmt.Errorf("failed to parse the %s file: %v", name, err)
				}
				s.InsertMany(list...)
			}
		}
		return nil
	}

	if args.Options.BruteForcing {
		if len(args.Filepaths.BruteWordlist) > 0 {
			if err := getList(args.Filepaths.BruteWordlist, "brute force wordlist", args.BruteWordList); err != nil {
				return err
			}
		} else {
			if f, err := resources.GetResourceFile("namelist.txt"); err == nil {
				if list, err := getWordList(f); err == nil {
					args.BruteWordList.InsertMany(list...)
				}
			}
		}
	}
	if !args.Options.NoAlts {
		if len(args.Filepaths.AltWordlist) > 0 {
			if err := getList(args.Filepaths.AltWordlist, "alterations wordlist", args.AltWordList); err != nil {
				return err
			}
		} else {
			if f, err := resources.GetResourceFile("alterations.txt"); err == nil {
				if list, err := getWordList(f); err == nil {
					args.AltWordList.InsertMany(list...)
				}
			}
		}
	}
	if err := getList([]string{args.Filepaths.Blacklist}, "blacklist", args.Blacklist); err != nil {
		return err
	}
	if err := getList([]string{args.Filepaths.ExcludedSrcs}, "exclude", args.Excluded); err != nil {
		return err
	}
	if err := getList([]string{args.Filepaths.IncludedSrcs}, "include", args.Included); err != nil {
		return err
	}
	if err := getList(args.Filepaths.Names, "subdomain names", args.Names); err != nil {
		return err
	}
	if err := getList(args.Filepaths.Domains, "domain names", args.Domains); err != nil {
		return err
	}
	if err := getList(args.Filepaths.Resolvers, "resolver", args.Resolvers); err != nil {
		return err
	}
	return nil
}

// Setup the amass enumeration settings
func (e enumArgs) OverrideConfig(conf *config.Config) error {
	if len(e.Addresses) > 0 {
		conf.Scope.Addresses = e.Addresses
	}
	if len(e.ASNs) > 0 {
		conf.Scope.ASNs = e.ASNs
	}
	if len(e.CIDRs) > 0 {
		conf.Scope.CIDRs = e.CIDRs
	}
	if len(e.Ports) > 0 {
		conf.Scope.Ports = e.Ports
	}
	if e.Filepaths.Directory != "" {
		conf.Dir = e.Filepaths.Directory
	}
	if e.Filepaths.ScriptsDirectory != "" {
		conf.ScriptsDirectory = e.Filepaths.ScriptsDirectory
	}
	if e.Names.Len() > 0 {
		conf.ProvidedNames = e.Names.Slice()
	}
	if e.BruteWordList.Len() > 0 {
		conf.Wordlist = e.BruteWordList.Slice()
	}
	if e.AltWordList.Len() > 0 {
		conf.AltWordlist = e.AltWordList.Slice()
	}
	if e.Options.BruteForcing {
		conf.BruteForcing = true
	}
	if e.Options.Alterations {
		conf.Alterations = true
	}
	if e.Options.NoRecursive {
		conf.Recursive = false
	}
	if e.MinForRecursive != 1 {
		conf.MinForRecursive = e.MinForRecursive
	}
	if e.MaxDepth != 0 {
		conf.MaxDepth = e.MaxDepth
	}
	if e.Options.Active {
		conf.Active = true
		conf.Passive = false
	}
	if e.Blacklist.Len() > 0 {
		conf.Scope.Blacklist = e.Blacklist.Slice()
	}
	if e.Options.Verbose {
		conf.Verbose = true
	}
	if e.ResolverQPS > 0 {
		conf.ResolversQPS = e.ResolverQPS
	}
	if e.TrustedQPS > 0 {
		conf.TrustedQPS = e.TrustedQPS
	}
	if e.Resolvers.Len() > 0 {
		conf.SetResolvers(e.Resolvers.Slice()...)
	}
	if e.Trusted.Len() > 0 {
		conf.SetTrustedResolvers(e.Trusted.Slice()...)
	}
	if e.MaxDNSQueries > 0 {
		conf.MaxDNSQueries = e.MaxDNSQueries
	}
	// Attempt to add the provided domains to the configuration
	conf.AddDomains(e.Domains.Slice()...)
	return nil
}
