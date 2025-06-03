// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package subs

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/internal/afmt"
	amassdb "github.com/owasp-amass/amass/v4/internal/db"
	amassnet "github.com/owasp-amass/amass/v4/internal/net"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

const (
	UsageMsg = "subs [options]"
)

type Args struct {
	Help    bool
	Domains *stringset.Set
	Options struct {
		DemoMode        bool
		IPs             bool
		IPv4            bool
		IPv6            bool
		ASNTableSummary bool
		DiscoveredNames bool
		NoColor         bool
		ShowAll         bool
		Silent          bool
	}
	Filepaths struct {
		ConfigFile string
		Directory  string
		Domains    string
		TermOut    string
	}
}

type outLookup map[string]*amassnet.Output

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("subs", errorHandling)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.Var(args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	fs.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	fs.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	fs.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	fs.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	fs.BoolVar(&args.Options.ASNTableSummary, "summary", false, "Print Just ASN Table Summary")
	fs.BoolVar(&args.Options.DiscoveredNames, "names", false, "Print Just Discovered Names")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.ShowAll, "show", false, "Print the results for the enumeration index + domains provided")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file. Additional details below")
	fs.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the graph database")
	fs.StringVar(&args.Filepaths.Domains, "df", "", "Path to a file providing root domain names")
	fs.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")
	return fs
}

func CLIWorkflow(clArgs []string) {
	var args Args
	args.Domains = stringset.New()
	defer args.Domains.Close()

	fs := NewFlagset(&args, flag.ContinueOnError)
	subsBuf := new(bytes.Buffer)
	fs.SetOutput(subsBuf)

	var usage = func() {
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), UsageMsg)
		fs.PrintDefaults()
		_, _ = afmt.G.Fprintln(color.Error, subsBuf.String())
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := fs.Parse(clArgs); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if args.Help {
		usage()
		return
	}
	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = io.Discard
		color.Error = io.Discard
	}
	if args.Options.IPs {
		args.Options.IPv4 = true
		args.Options.IPv6 = true
	}
	if args.Filepaths.Domains != "" {
		list, err := config.GetListFromFile(args.Filepaths.Domains)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to parse the domain names file: %v\n", err)
			return
		}
		args.Domains.InsertMany(list...)
	}

	cfg := config.NewConfig()
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		if args.Filepaths.Directory == "" {
			args.Filepaths.Directory = cfg.Dir
		}
		if args.Domains.Len() == 0 {
			args.Domains.InsertMany(cfg.Domains()...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	db := amassdb.OpenGraphDatabase(cfg)
	if db == nil {
		_, _ = afmt.R.Fprintln(color.Error, "Failed to connect with the database")
		os.Exit(1)
	}

	if args.Options.ShowAll {
		args.Options.DiscoveredNames = true
		args.Options.ASNTableSummary = true
	}
	if !args.Options.DiscoveredNames && !args.Options.ASNTableSummary {
		usage()
		return
	}

	var asninfo bool
	if args.Options.ASNTableSummary {
		asninfo = true
	}

	showData(&args, asninfo, db)
}

func showData(args *Args, asninfo bool, db repository.Repository) {
	var total int
	var err error
	var outfile *os.File
	domains := args.Domains.Slice()

	if args.Filepaths.TermOut != "" {
		outfile, err = os.OpenFile(args.Filepaths.TermOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to open the text output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			_ = outfile.Sync()
			_ = outfile.Close()
		}()
		_ = outfile.Truncate(0)
		_, _ = outfile.Seek(0, 0)
	}

	var cache *amassnet.ASNCache
	if asninfo {
		cache = amassnet.NewASNCache()
		if err := amassnet.FillCache(cache, db); err != nil {
			_, _ = afmt.R.Printf("Failed to populate the ASN cache: %v\n", err)
			return
		}
	}

	names := getNames(context.Background(), domains, asninfo, db)
	if len(names) != 0 && (asninfo || args.Options.IPv4 || args.Options.IPv6) {
		names = addAddresses(context.Background(), db, names, asninfo, cache)
	}

	asns := make(map[int]*amassnet.ASNSummaryData)
	for _, out := range names {
		if len(domains) > 0 && !domainNameInScope(out.Name, domains) {
			continue
		}

		if args.Options.IPv4 || args.Options.IPv6 {
			out.Addresses = afmt.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
		}

		if l := len(out.Addresses); (args.Options.IPv4 || args.Options.IPv6) && l == 0 {
			continue
		} else if l > 0 {
			afmt.UpdateSummaryData(out, asns)
		}

		total++
		name, ips := afmt.OutputLineParts(out, args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)
		if ips != "" {
			ips = " " + ips
		}

		if args.Options.DiscoveredNames {
			var written bool
			if outfile != nil {
				_, _ = fmt.Fprintf(outfile, "%s%s\n", name, ips)
				written = true
			}
			if !written {
				_, _ = fmt.Fprintf(color.Output, "%s%s\n", afmt.Green(name), afmt.Yellow(ips))
			}
		}
	}

	if total == 0 {
		_, _ = afmt.R.Println("No names were discovered")
		return
	}
	if args.Options.ASNTableSummary {
		var out io.Writer
		status := color.NoColor

		if outfile != nil {
			out = outfile
			color.NoColor = true
		} else if args.Options.ShowAll {
			out = color.Error
		} else {
			out = color.Output
		}

		afmt.FprintEnumerationSummary(out, total, asns, args.Options.DemoMode)
		color.NoColor = status
	}
}

func getNames(ctx context.Context, domains []string, asninfo bool, db repository.Repository) []*amassnet.Output {
	if len(domains) == 0 {
		return nil
	}

	qtime := time.Time{}
	filter := stringset.New()
	defer filter.Close()

	var assets []*dbt.Entity
	for _, d := range domains {
		if ents, err := db.FindEntitiesByContent(&oamdns.FQDN{Name: d}, qtime); err == nil && len(ents) == 1 {
			if n, err := amassdb.FindByFQDNScope(db, ents[0], qtime); err == nil && len(n) > 0 {
				assets = append(assets, n...)
			}
		}
	}
	if len(assets) == 0 {
		return nil
	}

	var names []*amassnet.Output
	for _, a := range assets {
		if n, ok := a.Asset.(*oamdns.FQDN); ok && !filter.Has(n.Name) {
			names = append(names, &amassnet.Output{Name: n.Name})
			filter.Insert(n.Name)
		}
	}
	return names
}

func addAddresses(ctx context.Context, db repository.Repository, names []*amassnet.Output, asninfo bool, cache *amassnet.ASNCache) []*amassnet.Output {
	var namestrs []string
	lookup := make(outLookup, len(names))
	for _, n := range names {
		lookup[n.Name] = n
		namestrs = append(namestrs, n.Name)
	}

	qtime := time.Time{}
	if pairs, err := amassnet.NamesToAddrs(db, qtime, namestrs...); err == nil {
		for _, p := range pairs {
			addr := p.Addr.Address.String()

			if p.FQDN.Name == "" || addr == "" {
				continue
			}
			if o, found := lookup[p.FQDN.Name]; found {
				o.Addresses = append(o.Addresses, amassnet.AddressInfo{Address: net.ParseIP(addr)})
			}
		}
	}

	if !asninfo || cache == nil {
		var output []*amassnet.Output
		for _, o := range lookup {
			if len(o.Addresses) > 0 {
				output = append(output, o)
			}
		}
		return output
	}
	return addInfrastructureInfo(lookup, cache)
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

func addInfrastructureInfo(lookup outLookup, cache *amassnet.ASNCache) []*amassnet.Output {
	output := make([]*amassnet.Output, 0, len(lookup))

	for _, o := range lookup {
		var newaddrs []amassnet.AddressInfo

		for _, a := range o.Addresses {
			i := cache.AddrSearch(a.Address.String())
			if i == nil {
				continue
			}

			_, netblock, _ := net.ParseCIDR(i.Prefix)
			newaddrs = append(newaddrs, amassnet.AddressInfo{
				Address:     a.Address,
				ASN:         i.ASN,
				CIDRStr:     i.Prefix,
				Netblock:    netblock,
				Description: i.Description,
			})
		}

		o.Addresses = newaddrs
		if len(o.Addresses) > 0 {
			output = append(output, o)
		}
	}
	return output
}
