// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/afmt"
)

// newArgs returns Args with its sets ready for the flags to fill.
func newArgs() Args {
	return Args{
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
		TrustedResolvers:  stringset.New(),
	}
}

func argsAndConfig(cmdName string, clArgs []string) (*config.Config, *Args) {
	args := newArgs()
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
	if args.Options.ListSources {
		printDataSources(cfg, color.Output)
		return nil, &args
	}
	if !cfg.HasSeed() {
		_, _ = afmt.R.Fprintln(color.Error,
			"Configuration error: no seed was provided (a domain, name, address, CIDR, ASN or organization)")
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
	if e.Engine != "" {
		conf.EngineAPI = &config.EngAPI{URL: e.Engine}
	}
	if e.Names.Len() > 0 {
		conf.AddSeedNames(e.Names.Slice()...)
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
	if e.Options.NoJoin {
		conf.SetJoinRunningJobs(false)
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
	if e.Interface != "" {
		conf.Interface = strings.TrimSpace(e.Interface)
	}
	if e.ActiveRoute != "" {
		conf.ActiveRoute = strings.TrimSpace(e.ActiveRoute)
	}
	if e.ActiveUDPRoute != "" {
		conf.ActiveUDPRoute = strings.TrimSpace(e.ActiveUDPRoute)
	}
	for _, r := range append(e.Resolvers.Slice(), e.TrustedResolvers.Slice()...) {
		if !config.IsResolverAddress(r) {
			return fmt.Errorf("the DNS resolver %q is not an IP address", r)
		}
	}
	if e.Resolvers.Len() > 0 {
		conf.SetResolvers(e.Resolvers.Slice()...)
	}
	if e.TrustedResolvers.Len() > 0 {
		conf.SetTrustedResolvers(e.TrustedResolvers.Slice()...)
	}
	// Attempt to add the provided domains to the configuration
	conf.AddDomains(e.Domains.Slice()...)
	return nil
}
