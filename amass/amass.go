// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

// Banner is the ASCII art logo used within help output.
const Banner = `

        .+++:.            :                             .+++.
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
        +o&&&&+.                                                    +oooo.

`

const (
	// Version is used to display the current version of Amass.
	Version = "3.0.12"

	// Author is used to display the Amass Project Team.
	Author = "OWASP Amass Project - @owaspamass"
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
)

// TrustedTag returns true when the tag parameter is of a type that should be trusted even
// facing DNS wildcards.
func TrustedTag(tag string) bool {
	if tag == core.DNS || tag == core.CERT || tag == core.ARCHIVE || tag == core.AXFR {
		return true
	}
	return false
}

// ASNSummaryData stores information related to discovered ASs and netblocks.
type ASNSummaryData struct {
	Name      string
	Netblocks map[string]int
}

// UpdateSummaryData updates the summary maps using the provided core.Output data.
func UpdateSummaryData(output *core.Output, tags map[string]int, asns map[int]*ASNSummaryData) {
	tags[output.Tag]++

	for _, addr := range output.Addresses {
		data, found := asns[addr.ASN]
		if !found {
			asns[addr.ASN] = &ASNSummaryData{
				Name:      addr.Description,
				Netblocks: make(map[string]int),
			}
			data = asns[addr.ASN]
		}
		// Increment how many IPs were in this netblock
		data.Netblocks[addr.Netblock.String()]++
	}
}

// PrintEnumerationSummary outputs the summary information utilized by the command-line tools.
func PrintEnumerationSummary(total int, tags map[string]int, asns map[int]*ASNSummaryData, demo bool) {
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			b.Fprint(color.Error, chr)
		}
	}

	fmt.Fprintln(color.Error)
	// Print the header information
	title := "OWASP Amass v"
	site := "https://github.com/OWASP/Amass"
	b.Fprint(color.Error, title+Version)
	num := 80 - (len(title) + len(Version) + len(site))
	pad(num, " ")
	b.Fprintf(color.Error, "%s\n", site)
	pad(8, "----------")
	fmt.Fprintf(color.Error, "\n%s%s", yellow(strconv.Itoa(total)), green(" names discovered - "))
	// Print the stats using tag information
	num, length := 1, len(tags)
	for k, v := range tags {
		fmt.Fprintf(color.Error, "%s: %s", green(k), yellow(strconv.Itoa(v)))
		if num < length {
			g.Fprint(color.Error, ", ")
		}
		num++
	}
	fmt.Fprintln(color.Error)

	if len(asns) == 0 {
		return
	}
	// Another line gets printed
	pad(8, "----------")
	fmt.Fprintln(color.Error)
	// Print the ASN and netblock information
	for asn, data := range asns {
		asnstr := strconv.Itoa(asn)
		datastr := data.Name

		if demo && asn > 0 {
			asnstr = censorString(asnstr, 0, len(asnstr))
			datastr = censorString(datastr, 0, len(datastr))
		}

		fmt.Fprintf(color.Error, "%s%s %s %s\n",
			blue("ASN: "), yellow(asnstr), green("-"), green(datastr))

		for cidr, ips := range data.Netblocks {
			countstr := strconv.Itoa(ips)
			cidrstr := cidr

			if demo {
				cidrstr = censorNetBlock(cidrstr)
			}

			countstr = fmt.Sprintf("\t%-4s", countstr)
			cidrstr = fmt.Sprintf("\t%-18s", cidrstr)

			fmt.Fprintf(color.Error, "%s%s %s\n",
				yellow(cidrstr), yellow(countstr), blue("Subdomain Name(s)"))
		}
	}
}

// PrintBanner outputs the Amass banner the same for all tools.
func PrintBanner() {
	y := color.New(color.FgHiYellow)
	r := color.New(color.FgHiRed)
	rightmost := 76
	version := "Version " + Version
	desc := "In-depth DNS Enumeration and Network Mapping"

	pad := func(num int) {
		for i := 0; i < num; i++ {
			fmt.Fprint(color.Error, " ")
		}
	}
	r.Fprintln(color.Error, Banner)
	pad(rightmost - len(version))
	y.Fprintln(color.Error, version)
	pad(rightmost - len(Author))
	y.Fprintln(color.Error, Author)
	pad(rightmost - len(desc))
	y.Fprintf(color.Error, "%s\n\n\n", desc)
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

// OutputLineParts returns the parts of a line to be printed for a core.Output.
func OutputLineParts(out *core.Output, src, addrs, demo bool) (source, name, ips string) {
	if src {
		source = fmt.Sprintf("%-18s", "["+out.Source+"] ")
	}
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
		if ips == "" {
			ips = "N/A"
		}
	}
	name = out.Name
	if demo {
		name = censorDomain(name)
	}
	return
}

// DesiredAddrTypes removes undesired address types from the AddressInfo slice.
func DesiredAddrTypes(addrs []core.AddressInfo, ipv4, ipv6 bool) []core.AddressInfo {
	if !ipv4 && !ipv6 {
		return addrs
	}

	var keep []core.AddressInfo
	for _, addr := range addrs {
		if utils.IsIPv4(addr.Address) && !ipv4 {
			continue
		} else if utils.IsIPv6(addr.Address) && !ipv6 {
			continue
		}
		keep = append(keep, addr)
	}
	return keep
}
