// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/utils"
)

var (
	filter     map[string]struct{}
	filterLock sync.Mutex
)

func main() {
	var addrs parseIPs
	var cidrs parseCIDRs
	var asns, ports parseInts
	filter = make(map[string]struct{})

	help := flag.Bool("h", false, "Show the program usage message")
	flag.Var(&addrs, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	flag.Var(&cidrs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	flag.Var(&asns, "asn", "ASNs separated by commas (can be used multiple times)")
	flag.Var(&ports, "p", "Ports separated by commas (default: 443)")
	flag.Parse()

	if *help {
		fmt.Printf("Usage: %s [--addr IP] [--cidr CIDR] [--asn number] [-p number]\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		return
	}

	done := make(chan struct{})
	results := make(chan string, 10)
	// Execute the signal handler
	go CatchSignals(results, done)

	if len(ports) == 0 {
		ports = []int{443}
	}

	if ips := AllIPsInScope(addrs, cidrs, asns); len(ips) > 0 {
		go PullAllCertificates(ips, ports, results)

		for domain := range results {
			fmt.Println(domain)
		}
	} else {
		fmt.Println("The parameters identified no hosts")
	}
	close(done)
}

func AllIPsInScope(addrs parseIPs, cidrs parseCIDRs, asns parseInts) []net.IP {
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

func PullAllCertificates(ips []net.IP, ports parseInts, output chan string) {
	var running int
	done := make(chan struct{}, 100)

	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			if running >= 100 || len(ips) <= 0 {
				continue
			}

			running++
			addr := ips[0]
			if len(ips) == 1 {
				ips = []net.IP{}
			} else {
				ips = ips[1:]
			}

			go ObtainCert(addr.String(), ports, output, done)
		case <-done:
			running--
			if running == 0 && len(ips) <= 0 {
				close(output)
				break loop
			}
		}
	}
}

func ObtainCert(addr string, ports parseInts, output chan string, done chan struct{}) {
	var domains []string

	for _, r := range amass.PullCertificateNames(addr, ports) {
		domains = utils.UniqueAppend(domains, r.Domain)
	}

	for _, domain := range domains {
		FilteredSend(domain, output)
	}
	done <- struct{}{}
}

func FilteredSend(domain string, output chan string) {
	filterLock.Lock()
	defer filterLock.Unlock()

	if _, found := filter[domain]; !found {
		output <- domain
		filter[domain] = struct{}{}
	}
}

// If the user interrupts the program, print the summary information
func CatchSignals(output chan string, done chan struct{}) {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// Wait for a signal
	<-sigs
	// Start final output operations
	close(output)
	// Wait for the broadcast indicating completion
	<-done
	os.Exit(1)
}
