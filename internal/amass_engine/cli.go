// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass_engine

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

const (
	UsageMsg    = "[options] [-log-dir path]"
	Description = "Run the Amass collection engine to populate the OAM database"
)

// ResolverQPSEnv sets the queries per second sent to each DNS resolver when
// the -resolver-qps flag is not given.
const ResolverQPSEnv = "AMASS_RESOLVER_QPS"

// InterfaceEnv names the network interface the engine's traffic leaves
// through when the -iface flag is not given.
const InterfaceEnv = "AMASS_IFACE"

// WorkerSessionsEnv sets how many running enumerations a pool worker joins
// at once when the -worker-sessions flag is not given.
const WorkerSessionsEnv = "AMASS_WORKER_SESSIONS"

// ActiveRouteEnv and ActiveUDPRouteEnv name the route the engine's active
// traffic takes, and the interface its active UDP leaves from, when the
// -active-route and -active-udp-route flags are not given.
const (
	ActiveRouteEnv    = "AMASS_ACTIVE_ROUTE"
	ActiveUDPRouteEnv = "AMASS_ACTIVE_UDP_ROUTE"
)

type Args struct {
	Help    bool
	Options struct {
		NoColor        bool
		Silent         bool
		ResolverQPS    int
		Interface      string
		ActiveRoute    string
		ActiveUDPRoute string
		Worker         bool
		WorkerSessions int
		Egress         string
	}
	Filepaths struct {
		LogDir     string
		ConfigFile string
		Dir        string
	}
}

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("engine", errorHandling)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.StringVar(&args.Filepaths.LogDir, "log-dir", "", "path to the log directory")
	fs.IntVar(&args.Options.ResolverQPS, "resolver-qps", -1, fmt.Sprintf("Queries per second sent to each "+
		"DNS resolver, across all enumerations; 0 for no limit (default %d, or $%s)",
		amassdns.DefaultResolverQPS, ResolverQPSEnv))
	fs.StringVar(&args.Options.Interface, "iface", "", fmt.Sprintf("Network interface (name or IP address) "+
		"the engine's traffic leaves through, unless an enumeration names its own (default $%s)", InterfaceEnv))
	fs.StringVar(&args.Options.ActiveRoute, "active-route", "", fmt.Sprintf("Route for active traffic: an "+
		"interface, or a proxy URL (socks5h://, socks5://, http://), unless an enumeration names its own "+
		"(default $%s)", ActiveRouteEnv))
	fs.StringVar(&args.Options.ActiveUDPRoute, "active-udp-route", "", fmt.Sprintf("Interface for active UDP "+
		"when the active route is a proxy (default $%s)", ActiveUDPRouteEnv))
	fs.BoolVar(&args.Options.Worker, "worker", false, "Join running enumerations on the configuration's "+
		"database as a pool worker, taking work from them when idle")
	fs.IntVar(&args.Options.WorkerSessions, "worker-sessions", 0, fmt.Sprintf("Running enumerations a pool "+
		"worker joins at once, one session for each (default %d, or $%s)", sessions.DefaultWorkerSessions,
		WorkerSessionsEnv))
	fs.StringVar(&args.Options.Egress, "egress", "", fmt.Sprintf("The engine's public IP address, which keeps a "+
		"second engine on the same address from working with the same database (default: asked of OpenDNS's "+
		"name servers at startup, or $%s)", amassnet.EgressEnv))
	fs.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the YAML configuration file a pool worker "+
		"takes its database and data source credentials from")
	fs.StringVar(&args.Filepaths.Dir, "dir", "", "Path to the directory containing the output files")
	return fs
}

func CLIWorkflow(cmdName string, clArgs []string) {
	var args Args
	fs := NewFlagset(&args, flag.ContinueOnError)

	engineBuf := new(bytes.Buffer)
	fs.SetOutput(engineBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", cmdName, UsageMsg)

		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, engineBuf.String())
			return
		}

		_, _ = afmt.G.Fprintln(color.Error, "Use the -h or --help flag to see the flags and default values")
		_, _ = afmt.G.Fprintf(color.Error, "\nThe Amass Discord server can be found here: %s\n\n", afmt.DiscordInvitation)
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

	qps, err := resolverQPS(args.Options.ResolverQPS, os.LookupEnv)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	amassdns.SetResolverQPS(qps)

	local, err := engineInterface(args.Options.Interface, os.LookupEnv)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	amassnet.SetLocalAddrs(local)

	route, err := engineActiveRoute(args.Options.ActiveRoute, args.Options.ActiveUDPRoute, os.LookupEnv)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	amassnet.SetActiveRoute(route)

	if a, err := engineEgress(args.Options.Egress, os.LookupEnv); err != nil {
		_, _ = afmt.Y.Fprintf(color.Error, "The engine's public address is unknown, so a second engine on the "+
			"same address can work with the same database: %v\n", err)
	} else {
		amassnet.SetEgress(a)
	}

	l, err := selectLogger(args.Filepaths.LogDir)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create the logger: %v", err)
		os.Exit(1)
	}

	e, err := engine.NewEngine(l)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to start the engine: %v", err)
		os.Exit(1)
	}
	defer e.Shutdown()

	if args.Options.Worker {
		cfg := config.NewConfig()
		if err := config.AcquireConfig(args.Filepaths.Dir, args.Filepaths.ConfigFile, cfg); err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to load the pool worker's configuration: %v\n", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		size, err := workerSessions(args.Options.WorkerSessions, os.LookupEnv)
		if err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
			os.Exit(1)
		}
		if err := sessions.StartPool(ctx, e.Manager, cfg, size); err != nil {
			_, _ = afmt.R.Fprintf(color.Error, "Failed to start the pool worker: %v\n", err)
			os.Exit(1)
		}
		l.Info("The engine is a pool worker", "sessions", size)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	<-quit
	l.Info("Terminating the collection engine")
}

// resolverQPS returns the engine's limit on queries per second per DNS
// resolver: the flag when given (zero or more), else the environment
// variable, else the default.
func resolverQPS(flagValue int, lookup func(string) (string, bool)) (int, error) {
	if flagValue >= 0 {
		return flagValue, nil
	}
	if v, ok := lookup(ResolverQPSEnv); ok && strings.TrimSpace(v) != "" {
		qps, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || qps < 0 {
			return 0, fmt.Errorf("%s must be a whole number of queries per second, not %q", ResolverQPSEnv, v)
		}
		return qps, nil
	}
	return amassdns.DefaultResolverQPS, nil
}

// engineInterface returns the local addresses of the engine's network
// interface: the flag's when given, else the environment variable's, else
// the zero LocalAddrs, which leaves the choice to the system.
func engineInterface(flagValue string, lookup func(string) (string, bool)) (amassnet.LocalAddrs, error) {
	local, err := amassnet.InterfaceAddrs(setting(flagValue, InterfaceEnv, lookup))
	if err != nil {
		return amassnet.LocalAddrs{}, fmt.Errorf("the engine's network interface: %w", err)
	}
	return local, nil
}

// engineActiveRoute returns the route of the engine's active traffic, from
// the flags when given, else the environment variables. Its proxy is not
// contacted here: it may start after the engine, and each enumeration checks
// it when it starts.
func engineActiveRoute(flagValue, udpFlagValue string, lookup func(string) (string, bool)) (amassnet.Route, error) {
	route, err := amassnet.ParseRoute(setting(flagValue, ActiveRouteEnv, lookup),
		setting(udpFlagValue, ActiveUDPRouteEnv, lookup))
	if err != nil {
		return amassnet.Route{}, fmt.Errorf("the engine's active route: %w", err)
	}
	return route, nil
}

// workerSessions returns how many running enumerations a pool worker joins
// at once: the flag when given (1 or more), else the environment variable,
// else sessions.DefaultWorkerSessions.
func workerSessions(flagValue int, lookup func(string) (string, bool)) (int, error) {
	if flagValue > 0 {
		return flagValue, nil
	}
	if v, ok := lookup(WorkerSessionsEnv); ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 {
			return 0, fmt.Errorf("%s must be a whole number of 1 or more, not %q", WorkerSessionsEnv, v)
		}
		return n, nil
	}
	return sessions.DefaultWorkerSessions, nil
}

// engineEgress returns the engine's public egress address: the flag's or
// the environment variable's when given, else the address OpenDNS's name
// servers see the engine's queries come from.
func engineEgress(flagValue string, lookup func(string) (string, bool)) (netip.Addr, error) {
	if v := setting(flagValue, amassnet.EgressEnv, lookup); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("the engine's public address %q: %w", v, err)
		}
		return a.Unmap(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return amassnet.FindEgress(ctx)
}

// setting returns the flag's value when given, else the environment
// variable's.
func setting(flagValue, env string, lookup func(string) (string, bool)) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	if v, ok := lookup(env); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func selectLogger(dir string) (*slog.Logger, error) {
	filename := fmt.Sprintf("amass_engine_%s.log", time.Now().Format("2006-01-02T15:04:05"))

	if dir != "" {
		return tools.NewFileLogger(dir, filename)
	}
	if l, err := tools.NewSyslogLogger(); err == nil && l != nil {
		return l, nil
	}

	dir = config.OutputDirectory("")
	if l, err := tools.NewFileLogger(dir, filename); err == nil && l != nil {
		return l, nil
	}

	return slog.New(slog.NewTextHandler(os.Stdout, nil)), nil
}
