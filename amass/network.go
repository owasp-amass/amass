// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strings"
	"time"

	"github.com/caffix/recon"
)

/* DNS processing routines */

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

func (a *Amass) ProcessDNSRequests() {
	wildcards := make(map[string]*recon.DnsWildcard)

	t := time.NewTicker(a.Frequency)
	defer t.Stop()

	for range t.C {
		subdomain := a.NextDNSRequest()
		if subdomain == nil || subdomain.Domain == "" {
			continue
		}
		domain := subdomain.Domain

		answers, err := a.dnsQuery(domain, subdomain.Name, "A")
		if err != nil {
			answers, err = a.dnsQuery(domain, subdomain.Name, "AAAA")
			if err != nil {
				continue
			}
		}

		ip := recon.GetARecordData(answers)
		if ip == "" {
			continue
		}

		if matchesWildcard(domain, subdomain.Name, ip, wildcards) {
			continue
		}

		// Return the successfully resolved name + address
		subdomain.Address = ip
		a.Resolved <- subdomain
	}
}

func (a *Amass) dnsQuery(domain, name, t string) ([]recon.DNSAnswer, error) {
	answers, err := recon.ResolveDNS(name, t)
	if err != nil {
		a.inspectDNSError(domain, err)
	}

	a.inspectDNSAnswers(domain, answers)
	return answers, err
}

func (a *Amass) inspectDNSError(domain string, err error) {
	re := SubdomainRegex(domain)

	for _, sd := range re.FindAllString(err.Error(), -1) {
		a.Names <- &Subdomain{Name: sd, Domain: domain, Tag: "dns"}
	}
}

func (a *Amass) inspectDNSAnswers(domain string, answers []recon.DNSAnswer) {
	re := SubdomainRegex(domain)

	for _, ans := range answers {
		for _, sd := range re.FindAllString(ans.Data, -1) {
			a.Names <- &Subdomain{Name: sd, Domain: domain, Tag: "dns"}
		}
	}
}

func matchesWildcard(baseDomain, name, ip string, wildcards map[string]*recon.DnsWildcard) bool {
	var result bool
	parts := strings.Split(name, ".")

	baseLen := len(strings.Split(baseDomain, "."))
	// Iterate over all the subdomains looking for wildcards
	for i := len(parts) - baseLen; i > 0; i-- {
		sub := strings.Join(parts[i:], ".")

		w, ok := wildcards[sub]
		if !ok {
			w = recon.CheckDomainForWildcard(sub)
			wildcards[sub] = w
		}

		if w.HasWildcard && w.IP == ip {
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
func (a *Amass) AttemptSweep(domain, addr string, filter func(string) bool) {
	// Check if the CIDR for this address needs to be swept
	cidr, _ := a.GetCIDR(addr)
	if cidr != nil {
		go a.sweepCIDRAddresses(domain, addr, cidr, filter)
	}
}

func (a *Amass) GetCIDR(addr string) (*CIDRData, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ip := net.ParseIP(addr)
	for _, data := range a.cidrCache {
		if data.CIDR.Contains(ip) {
			return data, true
		}
	}

	cidr := recon.IPToCIDR(addr)
	if cidr != "" {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
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

// Performs reverse dns across the CIDR that the addr param falls within
func (a *Amass) sweepCIDRAddresses(domain, addr string, cidr *CIDRData, filter func(string) bool) {
	t := time.NewTicker(a.Frequency)
	defer t.Stop()

	re := SubdomainRegex(domain)
	// Get the subset of 50 nearby IP addresses
	hosts := a.getCIDRSubset(cidr.Hosts, addr, 50)
	// Perform the reverse DNS queries for all the hosts
	for _, host := range hosts {
		if (filter != nil && filter(host)) || host == addr {
			continue
		}
		<-t.C // We can't be going too fast
		name, err := recon.ReverseDNS(host)
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

	for idx, ip := range hosts {
		if addr == ip {
			s := idx - offset
			if s < 0 {
				s = 0
			}

			e := idx + offset
			if e >= len(hosts) {
				e = len(hosts) - 1
			}

			return hosts[s:e]
		}
	}
	return hosts
}
