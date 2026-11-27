// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package afmt

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

// Banner is the ASCII art logo used within help output.
const Banner = `        .+++:.            :                             .+++.
      +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+
     &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&
    +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8
    8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:
    WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:
    #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8
    o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.
     WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o
     :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+
      :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&
        +o&&&&+.                                                    +oooo.`

const (
	// Version is used to display the current version of Amass.
	Version = "v5.1.3"

	// Author is used to display the Amass Project Team.
	Author = "OWASP Amass Project - @owaspamass"

	// Description is the slogan for the Amass Project.
	Description = "In-depth Attack Surface Mapping and Asset Discovery"

	// The URL to the Amass Project's Discord server.
	DiscordInvitation string = "https://discord.gg/ANTyEDUXt5"
)

var (
	// Colors used to ease the reading of program output
	B = color.New(color.FgHiBlue)
	Y = color.New(color.FgHiYellow)
	G = color.New(color.FgHiGreen)
	R = color.New(color.FgHiRed)
)

// PrintBanner outputs the Amass banner to stderr.
func PrintBanner() {
	FprintBanner(color.Error)
}

// FprintBanner outputs the Amass banner the same for all tools.
func FprintBanner(out io.Writer) {
	rightmost := 76

	pad := func(num int) {
		for i := 0; i < num; i++ {
			_, _ = fmt.Fprint(out, " ")
		}
	}

	_, _ = R.Fprintf(out, "\n%s\n\n", Banner)
	pad(rightmost - len(Version))
	_, _ = Y.Fprintln(out, Version)
	pad(rightmost - len(Author))
	_, _ = Y.Fprintln(out, Author)
	pad(rightmost - len(Description))
	_, _ = Y.Fprintf(out, "%s\n\n\n", Description)
}
