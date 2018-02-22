// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/recon"
)

// Public & free DNS servers
var nameservers []string = []string{
	"8.8.8.8:53",         // Google
	"64.6.64.6:53",       // Verisign
	"9.9.9.9:53",         // Quad9
	"84.200.69.80:53",    // DNS.WATCH
	"8.26.56.26:53",      // Comodo Secure DNS
	"208.67.222.222:53",  // OpenDNS Home
	"195.46.39.39:53",    // SafeDNS
	"69.195.152.204:53",  // OpenNIC
	"216.146.35.35:53",   // Dyn
	"37.235.1.174:53",    // FreeDNS
	"198.101.242.72:53",  // Alternate DNS
	"77.88.8.8:53",       // Yandex.DNS
	"91.239.100.100:53",  // UncensoredDNS
	"74.82.42.42:53",     // Hurricane Electric
	"156.154.70.1:53",    // Neustar
	"8.8.4.4:53",         // Google Secondary
	"64.6.65.6:53",       // Verisign Secondary
	"149.112.112.112:53", // Quad9 Secondary
	"84.200.70.40:53",    // DNS.WATCH Secondary
	"8.20.247.20:53",     // Comodo Secure DNS Secondary
	"208.67.220.220:53",  // OpenDNS Home Secondary
	"195.46.39.40:53",    // SafeDNS Secondary
	"216.146.36.36:53",   // Dyn Secondary
	"37.235.1.177:53",    // FreeDNS Secondary
	"23.253.163.53:53",   // Alternate DNS Secondary
	"77.88.8.1:53",       // Yandex.DNS Secondary
	"89.233.43.71:53",    // UncensoredDNS Secondary
	"156.154.71.1:53",    // Neustar Secondary
}

/* DNS processing routines */

func (a *Amass) processNextNameserver() {
	var index int
loop:
	for {
		select {
		case result := <-a.nextNameserver:
			index++
			if index == len(nameservers) {
				index = 0
			}

			result <- nameservers[index]
		case <-a.quit:
			break loop
		}
	}
	a.done <- struct{}{}
}

// NextNameserver - Requests the next server from the goroutine
func (a *Amass) NextNameserver() string {
	result := make(chan string, 2)

	a.nextNameserver <- result
	return <-result
}

// processDNSRequests - Executed as a go-routine to handle DNS processing
func (a *Amass) processDNSRequests() {
	var queue []*Subdomain

	t := time.NewTicker(a.Frequency)
	defer t.Stop()
loop:
	for {
		select {
		case add := <-a.addDNSRequest:
			queue = append(queue, add)
		case ans := <-a.dnsRequestQueueEmpty:
			if len(queue) == 0 {
				ans <- true
			} else {
				ans <- false
			}
		case <-t.C: // Pops a DNS name off the queue for resolution
			if len(queue) > 0 {
				next := queue[0]
				if next.Domain != "" {
					go a.performDNSRequest(next)
				}
				// Remove the first slice element
				if len(queue) > 1 {
					queue = queue[1:]
				} else {
					queue = []*Subdomain{}
				}
			}
		case <-a.quit:
			break loop
		}
	}
	a.done <- struct{}{}
}

// AddDNSRequest - Appends a DNS name to the queue for resolution
func (a *Amass) AddDNSRequest(name *Subdomain) {
	a.addDNSRequest <- name
}

// DNSRequestQueueEmpty - Checks if the queue for resolution is empty
func (a *Amass) DNSRequestQueueEmpty() bool {
	result := make(chan bool, 2)

	a.dnsRequestQueueEmpty <- result
	return <-result
}

func (a *Amass) performDNSRequest(subdomain *Subdomain) {
	answers, err := a.dnsQuery(subdomain.Domain, subdomain.Name, a.NextNameserver())
	if err != nil {
		a.Failed <- subdomain
		return
	}
	// Pull the IP address out of the DNS answers
	ipstr := recon.GetARecordData(answers)
	if ipstr == "" {
		a.Failed <- subdomain
		return
	}
	subdomain.Address = ipstr
	// Check that we didn't receive a wildcard IP address
	if a.matchesWildcard(subdomain) {
		a.Failed <- subdomain
		return
	}
	// Return the successfully resolved names + address
	for _, record := range answers {
		if !strings.HasSuffix(record.Name, subdomain.Domain) {
			continue
		}

		a.Resolved <- &Subdomain{
			Name:    record.Name,
			Domain:  subdomain.Domain,
			Address: ipstr,
			Tag:     subdomain.Tag,
		}
	}
}

// dnsQuery - Performs the DNS resolution and pulls names out of the errors or answers
func (a *Amass) dnsQuery(domain, name, server string) ([]recon.DNSAnswer, error) {
	var resolved bool
	var answers []recon.DNSAnswer
	var last recon.DNSAnswer

	n := name
	// Recursively resolve the CNAME records
	for i := 0; i < 10; i++ {
		a, err := recon.ResolveDNS(n, server, "CNAME")
		if err != nil {
			break
		}

		if strings.HasSuffix(n, domain) {
			answers = append(answers, a)
		}

		n = a.Data
		last = a
		resolved = true
	}
	// Attempt to update the name to be resolved for an A or AAAA record
	if resolved {
		name = last.Name
	}
	// Obtain the DNS answers for the A or AAAA records related to the name
	ans, err := recon.ResolveDNS(name, server, "A")
	if err != nil {
		ans, err = recon.ResolveDNS(name, server, "AAAA")
		if err != nil {
			return []recon.DNSAnswer{}, errors.New("No A or AAAA record resolved for the name")
		}
	}
	answers = append(answers, ans)
	return answers, err
}

type wildcard struct {
	Sub *Subdomain
	Ans chan bool
}

type dnsWildcard struct {
	HasWildcard bool
	IP          string
}

// Goroutine that keeps track of DNS wildcards discovered
func (a *Amass) processWildcardMatches() {
	wildcards := make(map[string]*dnsWildcard)
loop:
	for {
		select {
		case req := <-a.wildcardMatches:
			var answer bool

			labels := strings.Split(req.Sub.Name, ".")
			last := len(labels) - len(strings.Split(req.Sub.Domain, "."))
			// Iterate over all the subdomains looking for wildcards
			for i := 1; i <= last; i++ {
				sub := strings.Join(labels[i:], ".")

				w, ok := wildcards[sub]
				if !ok {
					w = a.checkDomainForWildcard(sub, req.Sub.Domain, a.NextNameserver())
					wildcards[sub] = w
				}

				if w.HasWildcard && w.IP == req.Sub.Address {
					answer = true
					break
				}
			}
			req.Ans <- answer
		case <-a.quit:
			break loop
		}
	}
	a.done <- struct{}{}
}

// checkDomainForWildcard detects if a domain returns an IP
// address for "bad" names, and if so, which address is used
func (a *Amass) checkDomainForWildcard(sub, root, server string) *dnsWildcard {
	var ip1, ip2, ip3 string

	name1 := "81very92unlikely03name." + sub
	name2 := "45another34random99name." + sub
	name3 := "just555little333me." + sub

	if a1, err := a.dnsQuery(root, name1, server); err == nil {
		ip1 = recon.GetARecordData(a1)
	}

	if a2, err := a.dnsQuery(root, name2, server); err == nil {
		ip2 = recon.GetARecordData(a2)
	}

	if a3, err := a.dnsQuery(root, name3, server); err == nil {
		ip3 = recon.GetARecordData(a3)
	}

	if ip1 != "" && (ip1 == ip2 && ip2 == ip3) {
		return &dnsWildcard{
			HasWildcard: true,
			IP:          ip1,
		}
	}
	return &dnsWildcard{
		HasWildcard: false,
		IP:          "",
	}
}

// matchesWildcard - Checks subdomains in the wildcard cache for matches on the IP address
func (a *Amass) matchesWildcard(subdomain *Subdomain) bool {
	answer := make(chan bool, 2)

	a.wildcardMatches <- &wildcard{
		Sub: subdomain,
		Ans: answer,
	}
	return <-answer
}

/* Network infrastructure related routines */

type CIDRData struct {
	CIDR  *net.IPNet
	Hosts []string
}

// AttemptSweep - Initiates a sweep of a subset of the addresses within the CIDR
// The filter param is optional and allows IP addresses to be filtered out
func (a *Amass) AttemptSweep(domain, addr string) {
	// Check if the CIDR for this address needs to be swept
	cidr := a.GetCIDR(addr)
	if cidr == nil {
		return
	}
	go a.sweepCIDRAddresses(domain, addr, cidr)
}

type getCIDR struct {
	Addr string
	CIDR chan *CIDRData
}

func obtainCIDR(addr string) (string, *CIDRData) {
	cidr := recon.IPToCIDR(addr)
	if cidr != "" {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			// Create the slice of all IP addresses within the CIDR
			hosts, err := recon.Hosts(cidr)
			if err == nil {
				return cidr, &CIDRData{
					CIDR:  ipnet,
					Hosts: hosts,
				}
			}
		}
	}
	return "", nil
}

// processGetCIDR - The cache of CIDR network blocks that have already been looked up.
// If the CIDR information isn't in the cache, it looks it up using the recon package
func (a *Amass) processGetCIDR() {
	cache := make(map[string]*CIDRData)
loop:
	for {
		select {
		case req := <-a.getCIDRInfo:
			var answer *CIDRData

			// Check the cache first for which CIDR this IP address falls within
			ip := net.ParseIP(req.Addr)
			for _, data := range cache {
				if data.CIDR.Contains(ip) {
					answer = data
					break
				}
			}
			// If the information was not within the cache, perform the lookup
			if answer == nil {
				cidr, data := obtainCIDR(req.Addr)
				if cidr != "" {
					cache[cidr] = data
					answer = data
				}
			}

			req.CIDR <- answer
		case <-a.quit:
			break loop
		}
	}
	a.done <- struct{}{}
}

// GetCIDR - Checks the cache for CIDR information related to the IP address provided.
func (a *Amass) GetCIDR(addr string) *CIDRData {
	cidr := make(chan *CIDRData, 2)

	a.getCIDRInfo <- &getCIDR{
		Addr: addr,
		CIDR: cidr,
	}
	return <-cidr
}

type reverseDNSFilter struct {
	Host string
	Ans  chan bool
}

// Prevents duplicate reverse DNS lookups being performed
func (a *Amass) processReverseDNSFilter() {
	filter := make(map[string]struct{})
	// Do not perform reverse lookups on localhost
	filter["127.0.0.1"] = struct{}{}
loop:
	for {
		select {
		case req := <-a.checkRDNSFilter:
			var answer bool

			if _, ok := filter[req.Host]; ok {
				answer = true
			} else {
				filter[req.Host] = struct{}{}
			}

			req.Ans <- answer
		case <-a.quit:
			break loop
		}
	}
	a.done <- struct{}{}
}

// Checks the reverse DNS filter to prevent duplicate lookups.
// Returns true if the host has been seen already
func (a *Amass) checkReverseDNSFilter(host string) bool {
	ans := make(chan bool, 2)

	a.checkRDNSFilter <- &reverseDNSFilter{
		Host: host,
		Ans:  ans,
	}
	return <-ans
}

// Performs reverse dns across the CIDR that the addr param falls within
func (a *Amass) sweepCIDRAddresses(domain, addr string, cidr *CIDRData) {
	t := time.NewTicker(a.Frequency)
	defer t.Stop()

	re := SubdomainRegex(domain)
	// Get the subset of 50 nearby IP addresses
	hosts := a.getCIDRSubset(cidr.Hosts, addr, 50)
	// Perform the reverse DNS queries for all the hosts
	for _, host := range hosts {
		// Check that duplicate lookups are not being performed
		if a.checkReverseDNSFilter(host) || host == addr {
			continue
		}
		<-t.C // Don't go too fast
		name, err := recon.ReverseDNS(host, a.NextNameserver())
		if err == nil && re.MatchString(name) {
			// Send the name to be resolved in the forward direction
			a.Names <- &Subdomain{
				Name:   name,
				Domain: domain,
				Tag:    "dns",
			}
		}
	}
}

// getCIDRSubset - Returns a subset of the hosts slice with num elements around the addr element
func (a *Amass) getCIDRSubset(hosts []string, addr string, num int) []string {
	offset := num / 2

	// Closure determines whether an IP address is less than or greater than another
	f := func(i int) bool {
		p1 := strings.Split(addr, ".")
		p2 := strings.Split(hosts[i], ".")

		for idx := 0; idx < len(p1); idx++ {
			n1, _ := strconv.Atoi(p1[idx])
			n2, _ := strconv.Atoi(p2[idx])

			if n2 < n1 {
				return false
			} else if n2 > n1 {
				return true
			}
		}
		return true
	}
	// Searches for the addr IP address in the hosts slice
	idx := sort.Search(len(hosts), f)
	if idx < len(hosts) && hosts[idx] == addr {
		// Now we determine the hosts elements to be included in the new slice
		s := idx - offset
		if s < 0 {
			s = 0
		}

		e := idx + offset + 1
		if e > len(hosts) {
			e = len(hosts)
		}
		return hosts[s:e]
	}
	// In the worst case, return the entire hosts slice
	return hosts
}
