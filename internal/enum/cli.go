// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/caffix/stringset"
	pb "github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/api/graphql/client"
	"github.com/owasp-amass/amass/v4/internal/afmt"
)

const (
	UsageMsg string = "[options] -d DOMAIN"
)

type Args struct {
	Help              bool
	Addresses         afmt.ParseIPs
	ASNs              afmt.ParseInts
	CIDRs             afmt.ParseCIDRs
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
	Ports             afmt.ParseInts
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
		AltWordlist      afmt.ParseStrings
		Blacklist        string
		BruteWordlist    afmt.ParseStrings
		ConfigFile       string
		Directory        string
		Domains          afmt.ParseStrings
		ExcludedSrcs     string
		IncludedSrcs     string
		JSONOutput       string
		LogFile          string
		Names            afmt.ParseStrings
		Resolvers        afmt.ParseStrings
		Trusted          afmt.ParseStrings
		ScriptsDirectory string
		TermOut          string
	}
}

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("enum", errorHandling)

	defineArgumentFlags(fs, args)
	defineOptionFlags(fs, args)
	defineFilepathFlags(fs, args)
	return fs
}

func defineArgumentFlags(fs *flag.FlagSet, args *Args) {
	fs.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	fs.Var(args.AltWordListMask, "awm", "\"hashcat-style\" wordlist masks for name alterations")
	fs.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	fs.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	fs.Var(args.Blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	fs.Var(args.BruteWordListMask, "wm", "\"hashcat-style\" wordlist masks for DNS brute forcing")
	fs.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	fs.Var(args.Excluded, "exclude", "Data source names separated by commas to be excluded")
	fs.Var(args.Included, "include", "Data source names separated by commas to be included")
	fs.StringVar(&args.Interface, "iface", "", "Provide the network interface to send traffic through")
	fs.IntVar(&args.MaxDNSQueries, "max-dns-queries", 0, "Deprecated flag to be replaced by dns-qps in version 4.0")
	fs.IntVar(&args.MaxDNSQueries, "dns-qps", 0, "Maximum number of DNS queries per second across all resolvers")
	fs.IntVar(&args.ResolverQPS, "rqps", 0, "Maximum number of DNS queries per second for each untrusted resolver")
	fs.IntVar(&args.TrustedQPS, "trqps", 0, "Maximum number of DNS queries per second for each trusted resolver")
	fs.IntVar(&args.MaxDepth, "max-depth", 0, "Maximum number of subdomain labels for brute forcing")
	fs.IntVar(&args.MinForRecursive, "min-for-recursive", 1, "Subdomain labels seen before recursive brute forcing (Default: 1)")
	fs.Var(&args.Ports, "p", "Ports separated by commas (default: 80, 443)")
	fs.Var(args.Resolvers, "r", "IP addresses of untrusted DNS resolvers (can be used multiple times)")
	fs.Var(args.Resolvers, "tr", "IP addresses of trusted DNS resolvers (can be used multiple times)")
	fs.IntVar(&args.Timeout, "timeout", 0, "Number of minutes to let enumeration run before quitting")
}

func defineOptionFlags(fs *flag.FlagSet, args *Args) {
	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.BoolVar(&args.Options.Active, "active", false, "Attempt zone transfers and certificate name grabs")
	fs.BoolVar(&args.Options.BruteForcing, "brute", false, "Execute brute forcing after searches")
	fs.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	fs.BoolVar(&args.Options.ListSources, "list", false, "Print the names of all available data sources")
	fs.BoolVar(&args.Options.Alterations, "alts", false, "Enable generation of altered names")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.NoRecursive, "norecursive", false, "Turn off recursive brute forcing")
	fs.BoolVar(&args.Options.Passive, "passive", false, "Deprecated since passive is the default setting")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.BoolVar(&args.Options.Verbose, "v", false, "Output status / debug / troubleshooting info")
}

func defineFilepathFlags(fs *flag.FlagSet, args *Args) {
	fs.StringVar(&args.Filepaths.AllFilePrefix, "oA", "", "Path prefix used for naming all output files")
	fs.Var(&args.Filepaths.AltWordlist, "aw", "Path to a different wordlist file for alterations")
	fs.StringVar(&args.Filepaths.Blacklist, "blf", "", "Path to a file providing blacklisted subdomains")
	fs.Var(&args.Filepaths.BruteWordlist, "w", "Path to a different wordlist file for brute forcing")
	fs.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
	fs.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the output files")
	fs.Var(&args.Filepaths.Domains, "df", "Path to a file providing root domain names")
	fs.StringVar(&args.Filepaths.ExcludedSrcs, "ef", "", "Path to a file providing data sources to exclude")
	fs.StringVar(&args.Filepaths.IncludedSrcs, "if", "", "Path to a file providing data sources to include")
	fs.StringVar(&args.Filepaths.LogFile, "log", "", "Path to the log file where errors will be written")
	fs.Var(&args.Filepaths.Names, "nf", "Path to a file providing already known subdomain names (from other tools/sources)")
	fs.Var(&args.Filepaths.Resolvers, "rf", "Path to a file providing untrusted DNS resolvers")
	fs.Var(&args.Filepaths.Trusted, "trf", "Path to a file providing trusted DNS resolvers")
	fs.StringVar(&args.Filepaths.ScriptsDirectory, "scripts", "", "Path to a directory containing ADS scripts")
	fs.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")
}

func CLIWorkflow(cmdName string, clArgs []string) {
	// Extract the correct config from the user provided arguments and/or configuration file
	cfg, args := argsAndConfig(cmdName, clArgs)
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
	token, err := client.CreateSession(cfg)
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
		_, _ = fmt.Println(err)
		return
	}

	var count int
	for _, a := range makeAssets(cfg) {
		if err := client.CreateAsset(*a, token); err == nil {
			count++
		}
	}

	var progress *pb.ProgressBar
	if !args.Options.Silent {
		progress = pb.Start64(int64(count))
	}

	done := make(chan struct{}, 1)
	go func() {
		var finished int
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-done:
				return
			case message := <-messages:
				writeLogMessage(l, message)
			case <-t.C:
				if stats, err := client.SessionStats(token); err == nil {
					if !args.Options.Silent {
						progress.SetTotal(int64(stats.WorkItemsTotal))
						progress.SetCurrent(int64(stats.WorkItemsCompleted))
					}

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
			}
		}
	}()

	if args.Timeout > 0 {
		go func() {
			t := time.NewTimer(time.Minute * time.Duration(args.Timeout))
			defer t.Stop()

			select {
			case <-done:
			case <-t.C:
				close(done)
			}
		}()
	}

	select {
	case <-done:
	case <-interrupt:
		close(done)
		return
	}

	if !args.Options.Silent {
		progress.Finish()
	}
}

func argsAndConfig(cmdName string, clArgs []string) (*config.Config, *Args) {
	args := Args{
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

	fs := NewFlagset(&args, flag.ContinueOnError)
	// set up the flag set to write errors to a buffer
	enumBuf := new(bytes.Buffer)
	fs.SetOutput(enumBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", cmdName, UsageMsg)

		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, enumBuf.String())
			return
		}

		_, _ = afmt.G.Fprintln(color.Error, "Use the -h or --help flag to see the flags and default values")
		_, _ = afmt.G.Fprintf(color.Error, "\nThe Amass Discord server can be found here: %s\n\n", afmt.DiscordInvitation)
	}

	if len(clArgs) < 1 {
		usage()
		return nil, &args
	}
	if err := fs.Parse(clArgs); err != nil {
		usage()
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if args.Help {
		usage()
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
		_, _ = afmt.R.Fprintln(color.Error, "Cannot provide both include and exclude arguments")
		usage()
		os.Exit(1)
	}
	if err := processInputFiles(&args); err != nil {
		_, _ = fmt.Fprintf(color.Error, "%v\n", err)
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
		_, _ = afmt.R.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}
	// Override configuration file settings with command-line arguments
	if err := cfg.UpdateConfig(args); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Configuration error: %v\n", err)
		os.Exit(1)
	}
	// Some input validation
	if !cfg.Active && len(args.Ports) > 0 {
		_, _ = afmt.R.Fprintln(color.Error, "Ports can only be scanned in the active mode")
		os.Exit(1)
	}
	if len(cfg.Domains()) == 0 {
		_, _ = afmt.R.Fprintln(color.Error, "Configuration error: No root domain names were provided")
		os.Exit(1)
	}
	return cfg, &args
}

// Setup the amass enumeration settings
func (e Args) OverrideConfig(conf *config.Config) error {
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
