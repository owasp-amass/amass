// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	amassnet "github.com/owasp-amass/amass/v4/net"
)

// ParseStrings implements the flag.Value interface.
type ParseStrings []string

// ParseInts implements the flag.Value interface.
type ParseInts []int

// ParseIPs implements the flag.Value interface.
type ParseIPs []net.IP

// ParseCIDRs implements the flag.Value interface.
type ParseCIDRs []*net.IPNet

// ParseASNs implements the flag.Value interface.
type ParseASNs []int

func (p *ParseStrings) String() string {
	if p == nil {
		return ""
	}
	return strings.Join(*p, ",")
}

// Set implements the flag.Value interface.
func (p *ParseStrings) Set(s string) error {
	if s == "" {
		return fmt.Errorf("String parsing failed")
	}

	str := strings.Split(s, ",")
	for _, s := range str {
		*p = append(*p, strings.TrimSpace(s))
	}
	return nil
}

func (p *ParseInts) String() string {
	if p == nil {
		return ""
	}
	var builder strings.Builder
	for i, n := range *p {
		if i > 0 {
			builder.WriteRune(',')
		}
		builder.WriteString(strconv.Itoa(n))
	}
	return builder.String()
}

// Set implements the flag.Value interface.
func (p *ParseInts) Set(s string) error {
	if s == "" {
		return fmt.Errorf("integer parsing failed")
	}

	nums := strings.Split(s, ",")
	for _, n := range nums {
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return err
		}
		*p = append(*p, i)
	}
	return nil
}

func (p *ParseIPs) String() string {
	if p == nil {
		return ""
	}
	var builder strings.Builder
	for i, ipaddr := range *p {
		if i > 0 {
			builder.WriteRune(',')
		}
		builder.WriteString(ipaddr.String())
	}
	return builder.String()
}

// Set implements the flag.Value interface.
func (p *ParseIPs) Set(s string) error {
	if s == "" {
		return fmt.Errorf("IP address parsing failed")
	}

	for _, v := range strings.Split(s, ",") {
		if start, end, ok := parseRange(v); ok {
			ips := amassnet.RangeHosts(start, end)
			if len(ips) == 0 {
				return fmt.Errorf("%s is not a valid IP address or range", v)
			}
			for _, ip := range ips {
				*p = append(*p, ip)
			}
			continue
		} else if ip := net.ParseIP(v); ip != nil {
			*p = append(*p, ip)
			continue
		} else {
			return fmt.Errorf("%s is not a valid IP address or range", v)
		}
	}
	return nil
}

func parseRange(s string) (start net.IP, end net.IP, ok bool) {
	twoIPs := strings.Split(s, "-")
	if len(twoIPs) != 2 {
		return
	}
	start = net.ParseIP(twoIPs[0])
	if start == nil {
		return
	}
	end = net.ParseIP(twoIPs[1])
	if end == nil {
		num, err := strconv.Atoi(twoIPs[1])
		if err != nil || math.MaxUint8 < num {
			return
		}
		end = make(net.IP, len(start))
		copy(end, start)
		end[len(end)-1] = byte(num)
	}
	ok = true
	return
}

func (p *ParseCIDRs) String() string {
	if p == nil {
		return ""
	}

	var builder strings.Builder
	for i, ipnet := range *p {
		if i > 0 {
			builder.WriteRune(',')
		}
		builder.WriteString(ipnet.String())
	}
	return builder.String()
}

// Set implements the flag.Value interface.
func (p *ParseCIDRs) Set(s string) error {
	if s == "" {
		return fmt.Errorf("%s is not a valid CIDR", s)
	}

	cidrs := strings.Split(s, ",")
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse %s as a CIDR", cidr)
		}

		*p = append(*p, ipnet)
	}
	return nil
}

func (p *ParseASNs) String() string {
	if p == nil {
		return ""
	}
	var builder strings.Builder
	for i, n := range *p {
		if i > 0 {
			builder.WriteRune(',')
		}
		builder.WriteString(strconv.Itoa(n))
	}
	return builder.String()
}

// Set implements the flag.Value interface.
func (p *ParseASNs) Set(s string) error {
	if s == "" {
		return fmt.Errorf("ASN parsing failed")
	}

	asns := strings.Split(s, ",")
	for _, asn := range asns {
		i, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(asn), "AS"))
		if err != nil {
			return err
		}
		*p = append(*p, i)
	}
	return nil
}
