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
	"os"
	"path"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/internal/afmt"
	"github.com/owasp-amass/amass/v4/internal/assoc"
	"github.com/owasp-amass/amass/v4/internal/enum"
	"github.com/owasp-amass/amass/v4/internal/subs"
	"github.com/owasp-amass/amass/v4/internal/track"
	"github.com/owasp-amass/amass/v4/internal/viz"
)

const (
	usageMsg string = "assoc|enum|subs|track|viz [options]"
)

func commandUsage(msg string, cmdFlagSet *flag.FlagSet, errBuf *bytes.Buffer) {
	afmt.PrintBanner()
	_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", path.Base(os.Args[0]), msg)
	cmdFlagSet.PrintDefaults()
	_, _ = afmt.G.Fprintln(color.Error, errBuf.String())

	if msg == usageMsg {
		_, _ = afmt.G.Fprintf(color.Error, "\nSubcommands: \n\n")
		_, _ = afmt.G.Fprintf(color.Error, "\t%-11s - Perform enumerations and network mapping\n", "amass enum")
	}

	_, _ = afmt.G.Fprintln(color.Error)
	_, _ = afmt.G.Fprintf(color.Error, "The Amass Discord server can be found here: \n%s\n\n", afmt.DiscordInvitation)
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
		commandUsage(usageMsg, mainFlagSet, defaultBuf)
		return
	}
	if err := mainFlagSet.Parse(os.Args[1:]); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(usageMsg, mainFlagSet, defaultBuf)
		return
	}
	if version {
		_, _ = afmt.G.Fprintf(color.Error, "%s\n", afmt.Version)
		return
	}

	cmdName := fmt.Sprintf("%s %s", path.Base(os.Args[0]), os.Args[1])
	switch os.Args[1] {
	case "assoc":
		assoc.CLIWorkflow(cmdName, os.Args[2:])
	case "enum":
		enum.CLIWorkflow(cmdName, os.Args[2:])
	case "subs":
		subs.CLIWorkflow(cmdName, os.Args[2:])
	case "track":
		track.CLIWorkflow(cmdName, os.Args[2:])
	case "viz":
		viz.CLIWorkflow(cmdName, os.Args[2:])
	default:
		commandUsage(usageMsg, mainFlagSet, defaultBuf)
		os.Exit(1)
	}
}
