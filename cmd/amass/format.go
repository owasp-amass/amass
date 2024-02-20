// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v4/format"
)

// ASNSummaryData stores information related to discovered ASs and netblocks.
type ASNSummaryData struct {
	Name      string
	Netblocks map[string]int
}

// DesiredAddrTypes removes undesired address types from the AddressInfo slice.
func DesiredAddrTypes(addrs []AddressInfo, ipv4, ipv6 bool) []AddressInfo {
	var kept []AddressInfo

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
func UpdateSummaryData(output *Output, asns map[int]*ASNSummaryData) {
	for _, addr := range output.Addresses {
		if addr.CIDRStr == "" {
			continue
		}

		data, found := asns[addr.ASN]
		if !found {
			asns[addr.ASN] = &ASNSummaryData{
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
func PrintEnumerationSummary(total int, asns map[int]*ASNSummaryData, demo bool) {
	FprintEnumerationSummary(color.Error, total, asns, demo)
}

// FprintEnumerationSummary outputs the summary information utilized by the command-line tools.
func FprintEnumerationSummary(out io.Writer, total int, asns map[int]*ASNSummaryData, demo bool) {
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			b.Fprint(out, chr)
		}
	}

	fmt.Fprintln(out)
	// Print the header information
	title := "OWASP Amass Project "
	site := "https://github.com/owasp-amass/amass"
	b.Fprint(out, title+format.Version)
	num := 80 - (len(title) + len(format.Version) + len(site))
	pad(num, " ")
	b.Fprintf(out, "%s\n", site)
	pad(8, "----------")
	fmt.Fprintf(out, "\n%s%s", yellow(strconv.Itoa(total)), green(" names discovered"))
	fmt.Fprintln(out)

	if len(asns) == 0 {
		return
	}
	// Another line gets printed
	pad(8, "----------")
	fmt.Fprintln(out)
	// Print the ASN and netblock information
	for asn, data := range asns {
		asnstr := strconv.Itoa(asn)
		datastr := data.Name

		if demo && asn > 0 {
			asnstr = censorString(asnstr, 0, len(asnstr))
			datastr = censorString(datastr, 0, len(datastr))
		}
		fmt.Fprintf(out, "%s%s %s %s\n", blue("ASN: "), yellow(asnstr), green("-"), green(datastr))

		for cidr, ips := range data.Netblocks {
			countstr := strconv.Itoa(ips)
			cidrstr := cidr

			if demo {
				cidrstr = censorNetBlock(cidrstr)
			}

			countstr = fmt.Sprintf("\t%-4s", countstr)
			cidrstr = fmt.Sprintf("\t%-18s", cidrstr)
			fmt.Fprintf(out, "%s%s %s\n", yellow(cidrstr), yellow(countstr), blue("Subdomain Name(s)"))
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
func OutputLineParts(out *Output, addrs, demo bool) (name, ips string) {
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
