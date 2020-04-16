// Copyright © by Jeff Foley 2017-2020. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// In-depth Attack Surface Mapping and Asset Discovery
//  +----------------------------------------------------------------------------+
//  | * * * ░░░░░░░░░░░░░░░░░░░░  OWASP Amass  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ |
//  +----------------------------------------------------------------------------+
//  |      .+++:.            :                             .+++.                 |
//  |    +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+   |
//  |   &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&   |
//  |  +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8         |
//  |  8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:       |
//  |  WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:     |
//  |  #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8    |
//  |  o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.  |
//  |   WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o  |
//  |   :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+  |
//  |    :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&   |
//  |      +o&&&&+.                                                    +oooo.    |
//  +----------------------------------------------------------------------------+
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/fatih/color"
)

const (
	mainUsageMsg         = "intel|enum|viz|track|db|dns [options]"
	exampleConfigFileURL = "https://github.com/OWASP/Amass/blob/master/examples/config.ini"
	userGuideURL         = "https://github.com/OWASP/Amass/blob/master/doc/user_guide.md"
	tutorialURL          = "https://github.com/OWASP/Amass/blob/master/doc/tutorial.md"
)

var (
	// Colors used to ease the reading of program output
	y      = color.New(color.FgHiYellow)
	g      = color.New(color.FgHiGreen)
	r      = color.New(color.FgHiRed)
	b      = color.New(color.FgHiBlue)
	fgR    = color.New(color.FgRed)
	fgY    = color.New(color.FgYellow)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	red   = color.New(color.FgHiRed).SprintFunc()
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
		g.Fprintf(color.Error, "\t%-11s - Visualize enumeration results\n", "amass viz")
		g.Fprintf(color.Error, "\t%-11s - Track differences between enumerations\n", "amass track")
		g.Fprintf(color.Error, "\t%-11s - Manipulate the Amass graph database\n", "amass db")
		g.Fprintf(color.Error, "\t%-11s - Resolve DNS names at high performance\n\n", "amass dns")
	}

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
	case "db":
		runDBCommand(os.Args[2:])
	case "dns":
		runDNSCommand(os.Args[2:])
	case "enum":
		runEnumCommand(os.Args[2:])
	case "intel":
		runIntelCommand(os.Args[2:])
	case "track":
		runTrackCommand(os.Args[2:])
	case "viz":
		runVizCommand(os.Args[2:])
	default:
		commandUsage(mainUsageMsg, mainFlagSet, defaultBuf)
		os.Exit(1)
	}
}

// GetAllSourceNames returns the names of all Amass data sources.
func GetAllSourceNames() []string {
	var names []string

	sys, err := systems.NewLocalSystem(config.NewConfig())
	if err != nil {
		return names
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys))

	for _, src := range sys.DataSources() {
		names = append(names, src.String())
	}

	sys.Shutdown()
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
