// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
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

	started   = make(chan struct{}, 50)
	done      = make(chan struct{}, 50)
	results   = make(chan string, 100)
	whoisChan = make(chan string, 100)
)

func main() {
	var whois bool
	var org string
	var addrs utils.ParseIPs
	var cidrs utils.ParseCIDRs
	var asns, ports utils.ParseInts

	help := flag.Bool("h", false, "Show the program usage message")
	flag.StringVar(&org, "org", "", "Search string provided against AS description information")
	flag.Var(&addrs, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	flag.Var(&cidrs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	flag.Var(&asns, "asn", "ASNs separated by commas (can be used multiple times)")
	flag.BoolVar(&whois, "whois", false, "All discovered domains are run through reverse whois")
	flag.Var(&ports, "p", "Ports separated by commas (default: 443)")

	defaultBuf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(defaultBuf)
	flag.Usage = func() {
		amass.PrintBanner()
		g.Fprintf(color.Error, "Usage: %s [--addr IP] [--cidr CIDR] [--asn number] [-p number]\n\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Fprintln(color.Error, defaultBuf.String())
	}
	flag.Parse()

	if *help || len(os.Args) == 1 {
		flag.Usage()
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
		r.Fprintln(color.Error, "The parameters identified no hosts")
		os.Exit(1)
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
				g.Println(d)
			}
		case domain := <-whoisChan:
			if !filter.Duplicate(domain) {
				g.Println(domain)
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
		started <- struct{}{}

		go func(ip net.IP) {
			if _, answer, err := amass.Reverse(ip.String()); err == nil {
				if d := strings.TrimSpace(amass.SubdomainToDomain(answer)); d != "" {
					results <- d
				}
			}
			done <- struct{}{}
		}(ip)
	}
}

func pullAllCertificates(ips []net.IP, ports utils.ParseInts) {
	maxPulls := utils.NewSimpleSemaphore(100)

	for _, ip := range ips {
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
			done <- struct{}{}
		}(ip)
	}
}

func allIPsInScope(addrs utils.ParseIPs, cidrs utils.ParseCIDRs, asns utils.ParseInts) []net.IP {
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
