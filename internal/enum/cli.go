// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/caffix/stringset"
	pb "github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/tools"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

const (
	UsageMsg    string = "[options] -d DOMAIN"
	Description string = "Interface with the engine that performs enumerations"
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
	Engine            string
	Excluded          *stringset.Set
	Included          *stringset.Set
	Interface         string
	ActiveRoute       string
	ActiveUDPRoute    string
	Phone             string
	Address           string
	MaxDepth          int
	MinForRecursive   int
	Names             *stringset.Set
	Ports             afmt.ParseInts
	Resolvers         *stringset.Set
	TrustedResolvers  *stringset.Set
	Timeout           int
	Options           struct {
		Active       bool
		Alterations  bool
		BruteForcing bool
		ListSources  bool
		NoColor      bool
		NoJoin       bool
		NoRecursive  bool
		Passive      bool
		Silent       bool
		Verbose      bool
	}
	Filepaths struct {
		AllFilePrefix string
		AltWordlist   afmt.ParseStrings
		Blacklist     string
		BruteWordlist afmt.ParseStrings
		ConfigFile    string
		Directory     string
		Domains       afmt.ParseStrings
		JSONOutput    string
		LogFile       string
		Names         afmt.ParseStrings
		Resolvers     afmt.ParseStrings
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
	fs.StringVar(&args.Engine, "engine", "", "URL for the collection engine (Default: http://127.0.0.1:4000)")
	fs.Var(args.Excluded, "exclude", "Data source names separated by commas to be excluded")
	fs.Var(args.Included, "include", "Data source names separated by commas to be included")
	fs.StringVar(&args.Interface, "iface", "", "Network interface (name or IP address) on the engine host to send traffic through")
	fs.StringVar(&args.ActiveRoute, "active-route", "", "Route for active traffic: an interface on the engine host, "+
		"or a proxy URL (socks5h://, socks5://, http://)")
	fs.StringVar(&args.ActiveUDPRoute, "active-udp-route", "", "Interface on the engine host for active UDP when "+
		"the active route is a proxy")
	fs.StringVar(&args.Phone, "phone", "", "Pivot from a phone number: enumerate the registered domains of the "+
		"organizations tied to it")
	fs.StringVar(&args.Address, "address", "", "Pivot from a street address: enumerate the registered domains of "+
		"the organizations at it (a shared or registered-agent address is reported, not enumerated)")
	fs.IntVar(&args.MaxDepth, "max-depth", 0, "Maximum number of subdomain labels for brute forcing")
	fs.IntVar(&args.MinForRecursive, "min-for-recursive", 1, "Subdomain labels seen before recursive brute forcing (Default: 1)")
	fs.Var(&args.Ports, "p", "Ports separated by commas (default: the FTP, SSH and mail ports and common web and management API ports)")
	fs.Var(args.Resolvers, "r", "IP addresses of untrusted DNS resolvers (can be used multiple times)")
	fs.Var(args.TrustedResolvers, "tr", "IP addresses of trusted DNS resolvers (can be used multiple times)")
	fs.IntVar(&args.Timeout, "timeout", 30, "Minutes to run without progress before terminating (Default: 30)")
}

func defineOptionFlags(fs *flag.FlagSet, args *Args) {
	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.BoolVar(&args.Options.Active, "active", false, "Attempt zone transfers and certificate name grabs")
	fs.BoolVar(&args.Options.BruteForcing, "brute", false, "Execute brute forcing after searches")
	fs.BoolVar(&args.Options.ListSources, "list", false, "Print the names of all available data sources")
	fs.BoolVar(&args.Options.Alterations, "alts", false, "Enable generation of altered names")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.NoJoin, "no-join", false, "Start a new enumeration even when other engines on the "+
		"database are already enumerating this scope, instead of joining theirs")
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
	fs.StringVar(&args.Filepaths.LogFile, "log", "", "Path to the log file where errors will be written")
	fs.Var(&args.Filepaths.Names, "nf", "Path to a file providing already known subdomain names (from other tools/sources)")
	fs.Var(&args.Filepaths.Resolvers, "rf", "Path to a file providing untrusted DNS resolvers")
}

func CLIWorkflow(cmdName string, clArgs []string) {
	// Extract the correct config from the user provided arguments and/or configuration file
	cfg, args := argsAndConfig(cmdName, clArgs)
	if cfg == nil {
		return
	}

	if err := tools.CreateOutputDirectory(cfg.Dir); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create the output directory: %v\n", err)
		os.Exit(1)
	}

	dir := config.OutputDirectory(cfg.Dir)
	if dir == "" {
		_, _ = afmt.R.Fprintln(color.Error, "failed to obtain the path for the output directory")
		os.Exit(1)
	}

	if err := tools.CreateDefaultConfigFiles(dir); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create the default config files: %v\n", err)
		os.Exit(1)
	}

	// A phone or address seed resolves to the registered domains of the
	// organizations tied to it, which are added to the scope before the run.
	// Resolution reads the database only; a shared address or a seed that
	// resolves to nothing stops here rather than enumerating.
	if !pivotSeedDomains(cfg, args, color.Error) {
		return
	}
	if !cfg.HasExpansionPolicy() {
		_, _ = afmt.Y.Fprintln(color.Error, "Note: "+config.NoPolicyWarning)
	}

	// Create the client that will provide a connection to the engine
	url := "http://127.0.0.1:4000"
	if cfg.EngineAPI != nil && cfg.EngineAPI.URL != "" {
		url = cfg.EngineAPI.URL
	}

	c, err := client.NewClient(url)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create an Amass engine API client: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a new enumeration session on the engine server
	created, err := c.NewSession(ctx, cfg)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create a session with the Amass engine: %v\n", err)
		os.Exit(1)
	}
	token := uuid.MustParse(created.SessionToken)
	if created.Joined {
		_, _ = afmt.Y.Fprintf(color.Error, "Joined the running enumeration of this scope (job %s), which other "+
			"engines on the database share; its configuration is used. Use -no-join to start a separate one.\n",
			created.JobID)
	}
	defer func() { _ = c.TerminateSession(context.Background(), token) }()

	logfile := args.Filepaths.LogFile
	if logfile == "" {
		logfile = fmt.Sprintf("session-%v.log", token)
	}

	l, err := selectLogger(dir, logfile)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create the logger: %v\n", err)
		os.Exit(1)
	}

	// Create interrupt channel and subscribe to server log messages
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	messages, err := c.Subscribe(ctx, token)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to subscribe to the Amass engine log messages: %v\n", err)
		os.Exit(1)
	}

	var count int
	// create all assets defined in the scope on the server
	// The enumeration starts from the seed; the scope only bounds it. With
	// no explicit seed, SeedScope falls back to the whole scope.
	for _, a := range convertScopeToAssets(cfg.SeedScope()) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if _, err := c.CreateAsset(ctx, token, a); err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to create asset on the engine: %v\n", err)
			continue
		}
		count++
	}

	// create the provided DNS names on the server using bulk transfer
	var fcount int
	var provFQDNs []oam.Asset
	for _, a := range cfg.ProvidedNames {
		fcount++
		provFQDNs = append(provFQDNs, oamdns.FQDN{Name: a})

		if fcount == client.MaxBulkItems {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			stored, err := c.CreateAssetsBulk(ctx, token, string(oam.FQDN), provFQDNs)
			if err != nil {
				_, _ = afmt.R.Fprintf(color.Error, "Failed to perform a bulk transfer of assets: %v\n", err)
			}

			count += stored
			fcount = 0
			provFQDNs = provFQDNs[:0]
		}
	}
	if fcount > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if stored, err := c.CreateAssetsBulk(ctx, token, string(oam.FQDN), provFQDNs); err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to perform a bulk transfer of assets: %v\n", err)
		} else {
			count += stored
		}
	}

	var progress *pb.ProgressBar
	if !args.Options.Silent {
		progress = pb.Start64(int64(count))
	}

	done := make(chan struct{}, 1)
	go func() {
		var previous, finished int
		var last *et.SessionStats
		timeoutDur := time.Duration(args.Timeout) * time.Minute

		term := time.NewTimer(timeoutDur)
		defer term.Stop()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-done:
				return
			case message := <-messages:
				if err := tools.WriteLogMessage(l, message); err != nil {
					fmt.Println(err.Error())
				}
			case <-t.C:
				if stats, err := getStats(c, token); err == nil && stats != nil {
					last = stats
					if !args.Options.Silent {
						stotal := max(count, stats.WorkItemsTotal)
						scomplete := max(0, stats.WorkItemsCompleted)

						progress.SetTotal(int64(stotal))
						progress.SetCurrent(int64(scomplete))
					}

					if comp := stats.WorkItemsCompleted; comp != previous {
						previous = comp
						_ = term.Reset(timeoutDur)
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
			case <-term.C:
				// Say why the session ends, so a stalled enumeration can be told
				// from one that finished its work.
				msg := fmt.Sprintf("No progress for %d minute(s); ending the session (-timeout).", args.Timeout)
				if last != nil {
					msg += fmt.Sprintf(" %d of %d work items were complete.", last.WorkItemsCompleted,
						last.WorkItemsTotal)
				}

				_, _ = afmt.Y.Fprintln(color.Error, msg)
				l.Warn(msg)
				close(done)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-interrupt:
		close(done)
	}

	if !args.Options.Silent {
		progress.Finish()
		fmt.Printf("\nSession Scope\n")
		printScope(c, token)
		printPendingProposals(cfg)
	}
}

// printPendingProposals tells the user, at the end of an enumeration, how many
// review proposals the run left waiting and of what kind, so the proposals
// surface on their own instead of only to someone who runs `amass review`. It
// reads the same journal the engine writes and `amass review` reads; the
// attribution pass holds the session open until it has recorded its proposals,
// so by the time the run is reported finished the journal already reflects it.
// It stays quiet when attribution is off, nothing is pending, or the journal
// is not reachable from here, so it never adds noise or an error to a run.
func printPendingProposals(cfg *config.Config) {
	mode, path, err := cfg.AIAttribution(os.LookupEnv)
	if err != nil || mode == config.AttributionOff || path == "" {
		return
	}

	// the journal is kept in the database when it keeps one
	repo := tools.OpenGraphDatabase(cfg)
	if repo != nil {
		defer func() { _ = repo.Close() }()
	}
	journal := review.OpenJournal(path, repo)
	summary, err := lenscli.PendingProposalsSummary(journal)
	if err != nil {
		return
	}
	if line := summary.Line(); line != "" {
		_, _ = afmt.G.Fprintf(color.Error, "\n%s\n", line)
	}

	if cfg.AnnounceAIDecisions(os.LookupEnv) {
		if applied, aerr := lenscli.AppliedByAISummary(journal, time.Time{}); aerr == nil {
			if line := applied.Line(); line != "" {
				_, _ = afmt.G.Fprintf(color.Error, "\n%s\n", line)
			}
		}
	}
}

func getStats(c *client.Client, token uuid.UUID) (*et.SessionStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return c.SessionStats(ctx, token)
}

func printScope(c *client.Client, token uuid.UUID) {
	for _, atype := range oam.AssetList {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		assets, err := c.SessionScope(ctx, token, atype)
		if err != nil {
			continue
		}

		fmt.Printf("\n%s:\n\n", atype)
		for _, a := range assets {
			name := a.Key()

			if o, valid := a.(*oamorg.Organization); valid {
				if o.LegalName != "" {
					name = o.LegalName
				} else if o.Name != "" {
					name = o.Name
				}
			}

			fmt.Println(name)
		}
	}
}
