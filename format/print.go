// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package format

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
	Version = "v4.2.0"

	// Author is used to display the Amass Project Team.
	Author = "OWASP Amass Project - @owaspamass"

	// Description is the slogan for the Amass Project.
	Description = "In-depth Attack Surface Mapping and Asset Discovery"
)

var (
	// Colors used to ease the reading of program output
	//b       = color.New(color.FgHiBlue)
	y = color.New(color.FgHiYellow)
	//g       = color.New(color.FgHiGreen)
	r = color.New(color.FgHiRed)
	//fgR     = color.New(color.FgRed)
	//fgY     = color.New(color.FgYellow)
	//yellow  = color.New(color.FgHiYellow).SprintFunc()
	//green   = color.New(color.FgHiGreen).SprintFunc()
	//blue    = color.New(color.FgHiBlue).SprintFunc()
	//magenta = color.New(color.FgHiMagenta).SprintFunc()
	//white   = color.New(color.FgHiWhite).SprintFunc()
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
			fmt.Fprint(out, " ")
		}
	}

	_, _ = r.Fprintf(out, "\n%s\n\n", Banner)
	pad(rightmost - len(Version))
	_, _ = y.Fprintln(out, Version)
	pad(rightmost - len(Author))
	_, _ = y.Fprintln(out, Author)
	pad(rightmost - len(Description))
	_, _ = y.Fprintf(out, "%s\n\n\n", Description)
}
