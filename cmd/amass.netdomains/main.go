// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/utils"
)

// Types that implement the flag.Value interface for parsing
type parseStrings []string
type parseIPs []net.IP
type parseCIDRs []*net.IPNet
type parseInts []int

var (
	started   = make(chan struct{}, 50)
	done      = make(chan struct{}, 50)
	results   = make(chan string, 100)
	whoisChan = make(chan string, 100)
)

func main() {
	var whois bool
	var org string
	var addrs parseIPs
	var cidrs parseCIDRs
	var asns, ports parseInts

	help := flag.Bool("h", false, "Show the program usage message")
	flag.StringVar(&org, "org", "", "Search string provided against AS description information")
	flag.Var(&addrs, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	flag.Var(&cidrs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	flag.Var(&asns, "asn", "ASNs separated by commas (can be used multiple times)")
	flag.BoolVar(&whois, "whois", false, "All discovered domains are run through reverse whois")
	flag.Var(&ports, "p", "Ports separated by commas (default: 443)")
	flag.Parse()

	if *help {
		fmt.Printf("Usage: %s [--addr IP] [--cidr CIDR] [--asn number] [-p number]\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		return
	}
	if len(ports) == 0 {
		ports = []int{443}
	}

	rand.Seed(time.Now().UTC().UnixNano())
	if org != "" {
		records, err := amass.LookupASNsByName(org)
		if err == nil {
			for _, a := range records {
				fmt.Printf("%d, %s, %s, %s\n", a.ASN, a.CC, a.Registry, a.Description)
			}
		} else {
			fmt.Printf("%v\n", err)
		}
		return
	}

	ips := allIPsInScope(addrs, cidrs, asns)
	if len(ips) == 0 {
		fmt.Println("The parameters identified no hosts")
		return
	}
	// Begin discovering all the domain names
	go performAllReverseDNS(ips)
	go pullAllCertificates(ips, ports)
	// Print all the unique domain names
	var count int
	filter := utils.NewStringFilter()
loop:
	for {
		select {
		case <-started:
			count++
		case <-done:
			count--
			if count == 0 {
				break loop
			}
		case d := <-results:
			if !filter.Duplicate(d) {
				if whois {
					go getWhoisDomains(d)
				}
				fmt.Println(d)
			}
		case domain := <-whoisChan:
			if !filter.Duplicate(domain) {
				fmt.Println(domain)
			}
		}
	}
}

func getWhoisDomains(d string) {
	domains, err := amass.ReverseWhois(d)
	if err != nil {
		return
	}
	for _, domain := range domains {
		if name := strings.TrimSpace(domain); name != "" {
			results <- name
		}
	}
}

func performAllReverseDNS(ips []net.IP) {
	for _, ip := range ips {
		amass.MaxConnections.Acquire(1)
		started <- struct{}{}

		go func(ip net.IP) {
			if _, answer, err := amass.Reverse(ip.String()); err == nil {
				if d := strings.TrimSpace(amass.SubdomainToDomain(answer)); d != "" {
					results <- d
				}
			}
			amass.MaxConnections.Release(1)
			done <- struct{}{}
		}(ip)
	}
}

func pullAllCertificates(ips []net.IP, ports parseInts) {
	maxPulls := utils.NewSimpleSemaphore(100)

	for _, ip := range ips {
		amass.MaxConnections.Acquire(1)
		maxPulls.Acquire(1)
		started <- struct{}{}

		go func(ip net.IP) {
			var domains []string
			for _, r := range amass.PullCertificateNames(ip.String(), ports) {
				domains = utils.UniqueAppend(domains, r.Domain)
			}
			for _, domain := range domains {
				if d := strings.TrimSpace(domain); d != "" {
					results <- d
				}
			}
			maxPulls.Release(1)
			amass.MaxConnections.Release(1)
			done <- struct{}{}
		}(ip)
	}
}

func allIPsInScope(addrs parseIPs, cidrs parseCIDRs, asns parseInts) []net.IP {
	var ips []net.IP

	ips = append(ips, addrs...)

	for _, cidr := range cidrs {
		ips = append(ips, utils.NetHosts(cidr)...)
	}

	for _, asn := range asns {
		record, err := amass.ASNRequest(asn)
		if err != nil {
			continue
		}

		for _, cidr := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			ips = append(ips, utils.NetHosts(ipnet)...)
		}
	}
	return ips
}

// parseStrings implementation of the flag.Value interface
func (p *parseStrings) String() string {
	if p == nil {
		return ""
	}
	return strings.Join(*p, ",")
}

func (p *parseStrings) Set(s string) error {
	if s == "" {
		return fmt.Errorf("String parsing failed")
	}

	str := strings.Split(s, ",")
	for _, s := range str {
		*p = append(*p, strings.TrimSpace(s))
	}
	return nil
}

// parseInts implementation of the flag.Value interface
func (p *parseInts) String() string {
	if p == nil {
		return ""
	}

	var nums []string
	for _, n := range *p {
		nums = append(nums, strconv.Itoa(n))
	}
	return strings.Join(nums, ",")
}

func (p *parseInts) Set(s string) error {
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

// parseIPs implementation of the flag.Value interface
func (p *parseIPs) String() string {
	if p == nil {
		return ""
	}

	var ipaddrs []string
	for _, ipaddr := range *p {
		ipaddrs = append(ipaddrs, ipaddr.String())
	}
	return strings.Join(ipaddrs, ",")
}

func (p *parseIPs) Set(s string) error {
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

func (p *parseIPs) appendIPs(addrs []net.IP) error {
	for _, addr := range addrs {
		*p = append(*p, addr)
	}
	return nil
}

func (p *parseIPs) parseRange(s string) error {
	twoIPs := strings.Split(s, "-")

	if twoIPs[0] == s {
		// This is not an IP range
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
		// These should have parsed properly
		return fmt.Errorf("%s is not a valid IP range", s)
	}
	return p.appendIPs(utils.RangeHosts(start, end))
}

// parseCIDRs implementation of the flag.Value interface
func (p *parseCIDRs) String() string {
	if p == nil {
		return ""
	}

	var cidrs []string
	for _, ipnet := range *p {
		cidrs = append(cidrs, ipnet.String())
	}
	return strings.Join(cidrs, ",")
}

func (p *parseCIDRs) Set(s string) error {
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
