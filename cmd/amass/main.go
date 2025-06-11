// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// In-depth Attack Surface Mapping and Asset Discovery
//
//	+----------------------------------------------------------------------------+
//	| ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  OWASP Amass  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ |
//	+----------------------------------------------------------------------------+
//	|      .+++:.            :                             .+++.                 |
//	|    +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+   |
//	|   &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&   |
//	|  +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8         |
//	|  8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:       |
//	|  WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:     |
//	|  #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8    |
//	|  o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.  |
//	|   WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o  |
//	|   :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+  |
//	|    :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&   |
//	|      +o&&&&+.                                                    +oooo.    |
//	+----------------------------------------------------------------------------+
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v4/engine/api/graphql/client"
	"github.com/owasp-amass/amass/v4/internal/afmt"
	ae "github.com/owasp-amass/amass/v4/internal/amass_engine"
	"github.com/owasp-amass/amass/v4/internal/assoc"
	"github.com/owasp-amass/amass/v4/internal/enum"
	"github.com/owasp-amass/amass/v4/internal/subs"
	"github.com/owasp-amass/amass/v4/internal/track"
	"github.com/owasp-amass/amass/v4/internal/viz"
)

const (
	usageMsg string = "[assoc|engine|enum|subs|track|viz] [options]"
)

type Args struct {
	Help    bool
	Version bool
}

type subDesc struct {
	Name        string
	Description string
}

var subcommands = []subDesc{
	{"assoc", assoc.Description},
	{"engine", ae.Description},
	{"enum", enum.Description},
	{"subs", subs.Description},
	{"track", track.Description},
	{"viz", viz.Description},
}

func main() {
	var args Args
	fs := flag.NewFlagSet("amass", flag.ContinueOnError)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.BoolVar(&args.Version, "version", false, "Print the Amass version number")

	defaultBuf := new(bytes.Buffer)
	fs.SetOutput(defaultBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), usageMsg)

		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, defaultBuf.String())
			_, _ = afmt.G.Fprintf(color.Error, "Subcommands: \n\n")
			for _, sub := range subcommands {
				_, _ = afmt.G.Fprintf(color.Error, "\t%-5s\t%s\n", sub.Name, sub.Description)
			}
			_, _ = afmt.G.Fprintln(color.Error)
			return
		}

		_, _ = afmt.G.Fprintln(color.Error, "Use the -h or --help flag to see the flags and subcommands")
		_, _ = afmt.G.Fprintf(color.Error, "\nThe Amass Discord server can be found here: %s\n\n", afmt.DiscordInvitation)
	}

	if len(os.Args) < 2 {
		usage()
		return
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		usage()
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if args.Help {
		usage()
		return
	}
	if args.Version {
		_, _ = afmt.G.Fprintf(color.Error, "%s\n", afmt.Version)
		return
	}

	cmdName := fmt.Sprintf("%s %s", path.Base(os.Args[0]), os.Args[1])
	switch os.Args[1] {
	case "assoc":
		assoc.CLIWorkflow(cmdName, os.Args[2:])
	case "engine":
		if engineIsRunning() {
			_, _ = afmt.R.Fprintf(color.Error, "The Amass engine is already running.\n")
			os.Exit(1)
		}

		ae.CLIWorkflow(cmdName, os.Args[2:])
	case "enum":
		// The engine must be started before running the enum command
		if !engineIsRunning() {
			if err := startEngine(); err != nil {
				_, _ = afmt.R.Fprintf(color.Error, "Failed to start the Amass engine: %v\n", err)
				os.Exit(1)
			}
			// Give the engine time to start
			time.Sleep(5 * time.Second)
			// Check if the engine is running after attempting to start it
			if !engineIsRunning() {
				_, _ = afmt.R.Fprintf(color.Error, "The Amass engine failed to start.\n")
				os.Exit(1)
			}
		}

		enum.CLIWorkflow(cmdName, os.Args[2:])
	case "subs":
		subs.CLIWorkflow(cmdName, os.Args[2:])
	case "track":
		track.CLIWorkflow(cmdName, os.Args[2:])
	case "viz":
		viz.CLIWorkflow(cmdName, os.Args[2:])
	default:
		usage()
		_, _ = afmt.R.Fprintf(color.Error, "subcommand provided but not defined: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func engineIsRunning() bool {
	c := client.NewClient("http://127.0.0.1:4000/graphql")

	if _, err := c.SessionStats(uuid.New()); err != nil && err.Error() == "invalid session token" {
		return true
	}
	return false
}

func startEngine() error {
	p, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	if p == "" {
		return fmt.Errorf("executable path is empty")
	}

	cmd := exec.Command("cmd", "/C", "start", p, "engine")
	if runtime.GOOS != "windows" {
		cmd = exec.Command("nohup", p, "engine")
		/*cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true, // Set the process group ID to allow for process management
		}*/
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Stdin = os.Stdin

	cmd.Dir, err = os.Getwd()
	if err != nil {
		return err
	}

	return cmd.Start()
}
