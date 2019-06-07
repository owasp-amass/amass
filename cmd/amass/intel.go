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
	"strings"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

const (
	intelUsageMsg = "intel [options]"
)

var (
	started   = make(chan struct{}, 50)
	done      = make(chan struct{}, 50)
	results   = make(chan string, 100)
	whoisChan = make(chan string, 100)
)

type intelArgs struct {
	Addresses        utils.ParseIPs
	ASNs             utils.ParseInts
	CIDRs            utils.ParseCIDRs
	OrganizationName string
	Ports            utils.ParseInts
	Options          struct {
		ReverseWhois bool
	}
}

func runIntelCommand(clArgs []string) {
	var args intelArgs
	var help1, help2 bool
	intelCommand := flag.NewFlagSet("intel", flag.ExitOnError)

	intelBuf := new(bytes.Buffer)
	intelCommand.SetOutput(intelBuf)

	intelCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	intelCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	intelCommand.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	intelCommand.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	intelCommand.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	intelCommand.StringVar(&args.OrganizationName, "org", "", "Search string provided against AS description information")
	intelCommand.Var(&args.Ports, "p", "Ports separated by commas (default: 443)")
	intelCommand.BoolVar(&args.Options.ReverseWhois, "whois", false, "All discovered domains are run through reverse whois")

	if len(clArgs) < 1 {
		commandUsage(intelUsageMsg, intelCommand, intelBuf)
		return
	}

	if err := intelCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(intelUsageMsg, intelCommand, intelBuf)
		return
	}

	// Some input validation
	if len(args.Ports) == 0 {
		args.Ports = []int{443}
	}

	rand.Seed(time.Now().UTC().UnixNano())

	if args.OrganizationName != "" {
		records, err := amass.LookupASNsByName(args.OrganizationName)
		if err == nil {
			for _, a := range records {
				fmt.Printf("%d, %s\n", a.ASN, a.Description)
			}
		} else {
			fmt.Printf("%v\n", err)
		}
		return
	}

	ips := allIPsInScope(args.Addresses, args.CIDRs, args.ASNs)
	if len(ips) == 0 {
		r.Fprintln(color.Error, "The parameters identified no hosts")
		os.Exit(1)
	}
	// Begin discovering all the domain names
	go performAllReverseDNS(ips)
	go pullAllCertificates(ips, args.Ports)
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
				if args.Options.ReverseWhois {
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
			if _, answer, err := core.ReverseDNS(ip.String()); err == nil {
				if d := strings.TrimSpace(core.SubdomainToDomain(answer)); d != "" {
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
/*
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
	}*/
	return ips
}
