// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package afmt

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/utils"
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
	B       = color.New(color.FgHiBlue)
	Y       = color.New(color.FgHiYellow)
	G       = color.New(color.FgHiGreen)
	R       = color.New(color.FgHiRed)
	FgR     = color.New(color.FgRed)
	FgY     = color.New(color.FgYellow)
	Yellow  = color.New(color.FgHiYellow).SprintFunc()
	Green   = color.New(color.FgHiGreen).SprintFunc()
	Blue    = color.New(color.FgHiBlue).SprintFunc()
	Magenta = color.New(color.FgHiMagenta).SprintFunc()
	White   = color.New(color.FgHiWhite).SprintFunc()
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

// DesiredAddrTypes removes undesired address types from the AddressInfo slice.
func DesiredAddrTypes(addrs []utils.AddressInfo, ipv4, ipv6 bool) []utils.AddressInfo {
	var kept []utils.AddressInfo

	for _, addr := range addrs {
		if ipv4 && IsIPv4(addr.Address) {
			kept = append(kept, addr)
		} else if ipv6 && IsIPv6(addr.Address) {
			kept = append(kept, addr)
		}
	}

	return kept
}

// IsIPv4 returns true when the provided net.IP address is an IPv4 address.
func IsIPv4(ip net.IP) bool {
	return strings.Count(ip.String(), ":") < 2
}

// IsIPv6 returns true when the provided net.IP address is an IPv6 address.
func IsIPv6(ip net.IP) bool {
	return strings.Count(ip.String(), ":") >= 2
}

// UpdateSummaryData updates the summary maps using the provided requests.Output data.
func UpdateSummaryData(output *utils.Output, asns map[int]*utils.ASNSummaryData) {
	for _, addr := range output.Addresses {
		if addr.CIDRStr == "" {
			continue
		}

		data, found := asns[addr.ASN]
		if !found {
			asns[addr.ASN] = &utils.ASNSummaryData{
				Name:      addr.Description,
				Netblocks: make(map[string]int),
			}
			data = asns[addr.ASN]
		}
		// Increment how many IPs were in this netblock
		data.Netblocks[addr.CIDRStr]++
	}
}

// PrintEnumerationSummary outputs the summary information utilized by the command-line tools.
func PrintEnumerationSummary(total int, asns map[int]*utils.ASNSummaryData, demo bool) {
	FprintEnumerationSummary(color.Error, total, asns, demo)
}

// FprintEnumerationSummary outputs the summary information utilized by the command-line tools.
func FprintEnumerationSummary(out io.Writer, total int, asns map[int]*utils.ASNSummaryData, demo bool) {
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			_, _ = B.Fprint(out, chr)
		}
	}

	_, _ = fmt.Fprintln(out)
	// Print the header information
	title := "OWASP Amass Project "
	site := "https://github.com/owasp-amass/amass"
	_, _ = B.Fprint(out, title+Version)
	num := 80 - (len(title) + len(Version) + len(site))
	pad(num, " ")
	_, _ = B.Fprintf(out, "%s\n", site)
	pad(8, "----------")
	_, _ = fmt.Fprintf(out, "\n%s%s", Yellow(strconv.Itoa(total)), Green(" names discovered"))
	_, _ = fmt.Fprintln(out)

	if len(asns) == 0 {
		return
	}
	// Another line gets printed
	pad(8, "----------")
	_, _ = fmt.Fprintln(out)
	// Print the ASN and netblock information
	for asn, data := range asns {
		asnstr := strconv.Itoa(asn)
		datastr := data.Name

		if demo && asn > 0 {
			asnstr = censorString(asnstr, 0, len(asnstr))
			datastr = censorString(datastr, 0, len(datastr))
		}
		_, _ = fmt.Fprintf(out, "%s%s %s %s\n", Blue("ASN: "), Yellow(asnstr), Green("-"), Green(datastr))

		for cidr, ips := range data.Netblocks {
			countstr := strconv.Itoa(ips)
			cidrstr := cidr

			if demo {
				cidrstr = censorNetBlock(cidrstr)
			}

			countstr = fmt.Sprintf("\t%-4s", countstr)
			cidrstr = fmt.Sprintf("\t%-18s", cidrstr)
			_, _ = fmt.Fprintf(out, "%s%s %s\n", Yellow(cidrstr), Yellow(countstr), Blue("Subdomain Name(s)"))
		}
	}
}

func censorString(input string, start, end int) string {
	runes := []rune(input)
	for i := start; i < end; i++ {
		if runes[i] == '.' ||
			runes[i] == '/' ||
			runes[i] == '-' ||
			runes[i] == ' ' {
			continue
		}
		runes[i] = 'x'
	}
	return string(runes)
}

func censorDomain(input string) string {
	return censorString(input, strings.Index(input, "."), len(input))
}

func censorIP(input string) string {
	return censorString(input, 0, strings.LastIndex(input, "."))
}

func censorNetBlock(input string) string {
	return censorString(input, 0, strings.Index(input, "/"))
}

// OutputLineParts returns the parts of a line to be printed for a requests.Output.
func OutputLineParts(out *utils.Output, addrs, demo bool) (name, ips string) {
	if addrs {
		for i, a := range out.Addresses {
			if i != 0 {
				ips += ","
			}
			if demo {
				ips += censorIP(a.Address.String())
			} else {
				ips += a.Address.String()
			}
		}
	}
	name = out.Name
	if demo {
		name = censorDomain(name)
	}
	return
}
