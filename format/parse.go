// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package format

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	amassnet "github.com/OWASP/Amass/v3/net"
)

// ParseStrings implements the flag.Value interface.
type ParseStrings []string

// ParseInts implements the flag.Value interface.
type ParseInts []int

// ParseIPs implements the flag.Value interface.
type ParseIPs []net.IP

// ParseCIDRs implements the flag.Value interface.
type ParseCIDRs []*net.IPNet

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

	var nums []string
	for _, n := range *p {
		nums = append(nums, strconv.Itoa(n))
	}
	return strings.Join(nums, ",")
}

// Set implements the flag.Value interface.
func (p *ParseInts) Set(s string) error {
	if s == "" {
		return fmt.Errorf("Integer parsing failed")
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

	var ipaddrs []string
	for _, ipaddr := range *p {
		ipaddrs = append(ipaddrs, ipaddr.String())
	}
	return strings.Join(ipaddrs, ",")
}

// Set implements the flag.Value interface.
func (p *ParseIPs) Set(s string) error {
	if s == "" {
		return fmt.Errorf("IP address parsing failed")
	}

	ips := strings.Split(s, ",")
	for _, ip := range ips {
		// Is this an IP range?
		err := p.parseRange(ip)
		if err == nil {
			continue
		}
		addr := net.ParseIP(ip)
		if addr == nil {
			return fmt.Errorf("%s is not a valid IP address or range", ip)
		}
		*p = append(*p, addr)
	}
	return nil
}

func (p *ParseIPs) appendIPs(addrs []net.IP) error {
	for _, addr := range addrs {
		*p = append(*p, addr)
	}
	return nil
}

func (p *ParseIPs) parseRange(s string) error {
	twoIPs := strings.Split(s, "-")

	if twoIPs[0] == s {
		return fmt.Errorf("%s is not a valid IP range", s)
	}
	start := net.ParseIP(twoIPs[0])
	end := net.ParseIP(twoIPs[1])
	if end == nil {
		num, err := strconv.Atoi(twoIPs[1])
		if err == nil {
			end = net.ParseIP(twoIPs[0])
			end[len(end)-1] = byte(num)
		}
	}
	if start == nil || end == nil {
		return fmt.Errorf("%s is not a valid IP range", s)
	}

	ips := amassnet.RangeHosts(start, end)
	if len(ips) == 0 {
		return fmt.Errorf("%s is not a valid IP range", s)
	}
	return p.appendIPs(ips)
}

func (p *ParseCIDRs) String() string {
	if p == nil {
		return ""
	}

	var cidrs []string
	for _, ipnet := range *p {
		cidrs = append(cidrs, ipnet.String())
	}
	return strings.Join(cidrs, ",")
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
			return fmt.Errorf("Failed to parse %s as a CIDR", cidr)
		}

		*p = append(*p, ipnet)
	}
	return nil
}
