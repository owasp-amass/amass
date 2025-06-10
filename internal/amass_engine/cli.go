// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass_engine

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine"
	"github.com/owasp-amass/amass/v4/engine/plugins"
	"github.com/owasp-amass/amass/v4/internal/afmt"
	"github.com/owasp-amass/amass/v4/internal/tools"
)

const (
	UsageMsg    = "[options] [-log-dir path]"
	Description = "Run the Amass collection engine to populate the OAM database"
)

type Args struct {
	Help    bool
	Options struct {
		NoColor bool
		Silent  bool
	}
	Filepaths struct {
		LogDir string
	}
}

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("engine", flag.ContinueOnError)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.StringVar(&args.Filepaths.LogDir, "log-dir", "", "path to the log directory")
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

	if err := plugins.LoadAndStartPlugins(e.Registry); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to start the plugins: %v", err)
		os.Exit(1)
	}

	if err := e.Registry.BuildPipelines(); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to build the handler pipelines: %v", err)
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	<-quit
	l.Info("Terminating the collection engine")
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
