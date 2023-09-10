// Copyright © by Jeff Foley 2017-2023. All rights reserved.
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
	"net"
	"os"
	"path"

	"github.com/caffix/service"
	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/format"
	amassnet "github.com/owasp-amass/amass/v4/net"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/config/config"
)

const (
	mainUsageMsg         = "intel|enum [options]"
	exampleConfigFileURL = "https://github.com/owasp-amass/amass/blob/master/examples/config.yaml"
	userGuideURL         = "https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md"
	tutorialURL          = "https://github.com/owasp-amass/amass/blob/master/doc/tutorial.md"
)

var (
	// Colors used to ease the reading of program output
	g       = color.New(color.FgHiGreen)
	r       = color.New(color.FgHiRed)
	fgR     = color.New(color.FgRed)
	fgY     = color.New(color.FgYellow)
	yellow  = color.New(color.FgHiYellow).SprintFunc()
	green   = color.New(color.FgHiGreen).SprintFunc()
	blue    = color.New(color.FgHiBlue).SprintFunc()
	magenta = color.New(color.FgHiMagenta).SprintFunc()
	white   = color.New(color.FgHiWhite).SprintFunc()
)

func commandUsage(msg string, cmdFlagSet *flag.FlagSet, errBuf *bytes.Buffer) {
	format.PrintBanner()
	g.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), msg)
	cmdFlagSet.PrintDefaults()
	g.Fprintln(color.Error, errBuf.String())

	if msg == mainUsageMsg {
		g.Fprintf(color.Error, "\nSubcommands: \n\n")
		g.Fprintf(color.Error, "\t%-11s - Discover targets for enumerations\n", "amass intel")
		g.Fprintf(color.Error, "\t%-11s - Perform enumerations and network mapping\n", "amass enum")
	}

	g.Fprintln(color.Error)
	g.Fprintf(color.Error, "The user's guide can be found here: \n%s\n\n", userGuideURL)
	g.Fprintf(color.Error, "An example configuration file can be found here: \n%s\n\n", exampleConfigFileURL)
	g.Fprintf(color.Error, "The Amass tutorial can be found here: \n%s\n\n", tutorialURL)
}

func main() {
	var version, help1, help2 bool
	mainFlagSet := flag.NewFlagSet("amass", flag.ContinueOnError)

	defaultBuf := new(bytes.Buffer)
	mainFlagSet.SetOutput(defaultBuf)

	mainFlagSet.BoolVar(&help1, "h", false, "Show the program usage message")
	mainFlagSet.BoolVar(&help2, "help", false, "Show the program usage message")
	mainFlagSet.BoolVar(&version, "version", false, "Print the version number of this Amass binary")

	if len(os.Args) < 2 {
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		return
	}
	if err := mainFlagSet.Parse(os.Args[1:]); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		return
	}
	if version {
		fmt.Fprintf(color.Error, "%s\n", format.Version)
		return
	}

	switch os.Args[1] {
	case "enum":
		runEnumCommand(os.Args[2:])
	case "intel":
		runIntelCommand(os.Args[2:])
	case "help":
		runHelpCommand(os.Args[2:])
	default:
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		os.Exit(1)
	}
}

// GetAllSourceInfo returns the output for the 'list' flag.
func GetAllSourceInfo(cfg *config.Config) []string {
	if cfg == nil {
		cfg = config.NewConfig()
	}

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return []string{}
	}
	defer func() { _ = sys.Shutdown() }()

	srcs := datasrcs.SelectedDataSources(cfg, datasrcs.GetAllSources(sys))
	if err := sys.SetDataSources(srcs); err != nil {
		return []string{}
	}
	return DataSourceInfo(srcs, sys)
}

// DataSourceInfo acquires the information for data sources used by the provided System.
func DataSourceInfo(all []service.Service, sys systems.System) []string {
	var names []string

	names = append(names, fmt.Sprintf("%-35s%-35s%s", blue("Data Source"), blue("| Type"), blue("| Available")))
	var line string
	for i := 0; i < 8; i++ {
		line += blue("----------")
	}
	names = append(names, line)

	available := sys.DataSources()
	for _, src := range all {
		var avail string

		for _, a := range available {
			if src.String() == a.String() {
				avail = "*"
				break
			}
		}

		names = append(names, fmt.Sprintf("%-35s  %-35s  %s",
			green(src.String()), yellow(src.Description()), yellow(avail)))
	}

	return names
}

func createOutputDirectory(cfg *config.Config) {
	// Prepare output file paths
	dir := config.OutputDirectory(cfg.Dir)
	if dir == "" {
		r.Fprintln(color.Error, "Failed to obtain the output directory")
		os.Exit(1)
	}
	// If the directory does not yet exist, create it
	if err := os.MkdirAll(dir, 0755); err != nil {
		r.Fprintf(color.Error, "Failed to create the directory: %v\n", err)
		os.Exit(1)
	}
}

func assignNetInterface(iface *net.Interface) error {
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("network interface '%s' has no assigned addresses", iface.Name)
	}

	var best net.Addr
	for _, addr := range addrs {
		if a, ok := addr.(*net.IPNet); ok {
			if best == nil {
				best = a
			}
			if amassnet.IsIPv4(a.IP) {
				best = a
				break
			}
		}
	}

	if best == nil {
		return fmt.Errorf("network interface '%s' does not have assigned IP addresses", iface.Name)
	}

	amassnet.LocalAddr = best
	return nil
}
