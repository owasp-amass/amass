// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	//"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/recon"
)

// Public & free DNS servers
var nameservers []string = []string{
	"8.8.8.8:53",        // Google
	"64.6.64.6:53",      // Verisign
	"9.9.9.9:53",        // Quad9
	"84.200.69.80:53",   // DNS.WATCH
	"8.26.56.26:53",     // Comodo Secure DNS
	"208.67.222.222:53", // OpenDNS Home
	"195.46.39.39:53",   // SafeDNS
	"69.195.152.204:53", // OpenNIC
	"216.146.35.35:53",  // Dyn
	"37.235.1.174:53",   // FreeDNS
	"198.101.242.72:53", // Alternate DNS
	"77.88.8.8:53",      // Yandex.DNS
	"91.239.100.100:53", // UncensoredDNS
	"74.82.42.42:53",    // Hurricane Electric
	"156.154.70.1:53",   // Neustar
}

/* DNS processing routines */

// NextNameserver - Atomically increments the index and returns the server
func (a *Amass) NextNameserver() string {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.DNSServerIndex++
	// Check if it's time to go back to the first nameserver
	if a.DNSServerIndex == len(nameservers) {
		a.DNSServerIndex = 0
	}
	return nameservers[a.DNSServerIndex]
}

// AddDNSRequest - Appends a DNS name to the queue for resolution
func (a *Amass) AddDNSRequest(name *Subdomain) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.DNSResolveQueue = append(a.DNSResolveQueue, name)
}

// NextDNSRequest - Pops a DNS name off the queue for resolution
func (a *Amass) NextDNSRequest() *Subdomain {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if len(a.DNSResolveQueue) == 0 {
		return nil
	}

	next := a.DNSResolveQueue[0]
	if len(a.DNSResolveQueue) > 1 {
		a.DNSResolveQueue = a.DNSResolveQueue[1:]
	} else {
		a.DNSResolveQueue = []*Subdomain{}
	}
	return next
}

// DNSRequestQueueEmpty - Checks if the queue for resolution is empty
func (a *Amass) DNSRequestQueueEmpty() bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return len(a.DNSResolveQueue) == 0
}

// processDNSRequests - Executed as a go-routine to perform the forward DNS queries
func (a *Amass) processDNSRequests() {
	t := time.NewTicker(a.Frequency)
	defer t.Stop()

	for range t.C {
		subdomain := a.NextDNSRequest()

		if subdomain != nil && subdomain.Domain != "" {
			go a.performDNSRequest(subdomain)
		}
	}
}

func (a *Amass) performDNSRequest(subdomain *Subdomain) {
	domain := subdomain.Domain
	server := a.NextNameserver()

	answers, err := a.dnsQuery(domain, subdomain.Name, server)
	if err != nil {
		return
	}
	// Pull the IP address out of the DNS answers
	ipstr := recon.GetARecordData(answers)
	if ipstr == "" {
		return
	}
	/*if ipstr == "104.239.213.7" {
		fmt.Printf("Query for %s on server %s returned 104.239.213.7\n", subdomain.Name, server)
		return
	}*/
	subdomain.Address = ipstr
	// Check that we didn't receive a wildcard IP address
	if a.matchesWildcard(subdomain) {
		return
	}
	// Return the successfully resolved names + address
	for _, record := range answers {
		if record.Type == 5 || (record.Type == 1 &&
			strings.HasSuffix(record.Name, subdomain.Domain)) {
			a.Resolved <- &Subdomain{
				Name:    record.Name,
				Domain:  subdomain.Domain,
				Address: ipstr,
				Tag:     subdomain.Tag,
			}
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
		a.inspectDNSError(domain, err)
		ans, err = recon.ResolveDNS(name, server, "AAAA")
		if err != nil {
			a.inspectDNSError(domain, err)
			return []recon.DNSAnswer{}, errors.New("No A or AAAA record resolved for the name")
		}
	}
	a.inspectDNSAnswers(domain, ans)
	answers = append(answers, ans)
	return answers, err
}

// inspectDNSError - Checks the DNS error for names
func (a *Amass) inspectDNSError(domain string, err error) {
	re := SubdomainRegex(domain)

	for _, sd := range re.FindAllString(err.Error(), -1) {
		a.Names <- &Subdomain{Name: sd, Domain: domain, Tag: "dns"}
	}
}

// inspectDNSAnswers - Checks the DNS answers for names
func (a *Amass) inspectDNSAnswers(domain string, answer recon.DNSAnswer) {
	re := SubdomainRegex(domain)

	for _, sd := range re.FindAllString(answer.Data, -1) {
		a.Names <- &Subdomain{Name: sd, Domain: domain, Tag: "dns"}
	}
}

// matchesWildcard - Checks subdomains in the wildcard cache for matches on the IP address
func (a *Amass) matchesWildcard(subdomain *Subdomain) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	var result bool
	parts := strings.Split(subdomain.Name, ".")

	baseLen := len(strings.Split(subdomain.Domain, "."))
	// Iterate over all the subdomains looking for wildcards
	for i := len(parts) - baseLen; i > 0; i-- {
		sub := strings.Join(parts[i:], ".")

		w, ok := a.wildcards[sub]
		if !ok {
			w = recon.CheckDomainForWildcard(sub, nameservers[0])
			a.wildcards[sub] = w
		}

		if w.HasWildcard && w.IP == subdomain.Address {
			result = true
			break
		}
	}
	return result
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
	cidr, _ := a.GetCIDR(addr)
	if cidr != nil {
		go a.sweepCIDRAddresses(domain, addr, cidr)
	}
}

// GetCIDR - Checks the cache for CIDR information related to the IP address provided.
// If the CIDR information isn't in the cache, it looks it up using the recon package
func (a *Amass) GetCIDR(addr string) (*CIDRData, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	// Check the cache first for which CIDR this IP address falls within
	ip := net.ParseIP(addr)
	for _, data := range a.cidrCache {
		if data.CIDR.Contains(ip) {
			return data, true
		}
	}
	// If the information was not within the cache, perform the lookup
	cidr := recon.IPToCIDR(addr)
	if cidr != "" {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			// Create the slice of all IP addresses within the CIDR
			hosts, err := recon.Hosts(cidr)
			if err == nil {
				a.cidrCache[cidr] = &CIDRData{
					CIDR:  ipnet,
					Hosts: hosts,
				}
				return a.cidrCache[cidr], false
			}
		}
	}
	return nil, false
}

// Checks the reverse DNS filter to prevent duplicate lookups.
// Returns true if the host has been seen already
func (a *Amass) checkReverseDNSFilter(host string) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if _, ok := a.rDNSFilter[host]; ok {
		return true
	}

	a.rDNSFilter[host] = struct{}{}
	return false
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
