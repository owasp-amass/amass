// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"net"
	"strconv"
	"strings"

	amassnet "github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/miekg/dns"
)

func (e *Enumeration) newNameEvent(req *requests.DNSRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	req.Name = strings.ToLower(amassdns.RemoveAsteriskLabel(req.Name))
	req.Name = strings.Trim(req.Name, ".")
	req.Domain = strings.ToLower(req.Domain)

	// Filter on the DNS name + the value from TrustedTag
	if e.filters.NewNames.Duplicate(req.Name +
		strconv.FormatBool(requests.TrustedTag(req.Tag))) {
		return
	}

	if e.Config.Passive {
		e.updateLastActive("enum")
		if e.Config.IsDomainInScope(req.Name) {
			e.Bus.Publish(requests.OutputTopic, &requests.Output{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}

	e.Bus.Publish(requests.ResolveNameTopic, e.ctx, req)
}

func (e *Enumeration) newResolvedName(req *requests.DNSRequest) {
	req.Name = strings.ToLower(amassdns.RemoveAsteriskLabel(req.Name))
	req.Name = strings.Trim(req.Name, ".")
	req.Domain = strings.ToLower(req.Domain)

	// Write the DNS name information to the graph databases
	e.dataMgr.DNSRequest(e.ctx, req)

	// Add addresses that are relevant to the enumeration
	if !e.hasCNAMERecord(req) && e.hasARecords(req) {
		for _, r := range req.Records {
			t := uint16(r.Type)

			if t == dns.TypeA || t == dns.TypeAAAA {
				e.addAddress(r.Data)
			}
		}
	}

	/*
	 * Do not go further if the name is not in scope or been seen before
	 */
	if e.filters.Resolved.Duplicate(req.Name) ||
		!e.Config.IsDomainInScope(req.Name) {
		return
	}

	// Put the DNS name + records on the queue for output processing
	if e.hasARecords(req) {
		e.resolvedQueue.Append(req)
	}

	// Keep track of all domains and proper subdomains discovered
	e.checkSubdomain(req)

	if e.Config.BruteForcing && e.Config.Recursive {
		for _, name := range topNames {
			e.newNameEvent(&requests.DNSRequest{
				Name:   name + "." + req.Name,
				Domain: req.Domain,
				Tag:    requests.GUESS,
				Source: "Enum Probes",
			})
		}
	}

	// Queue the resolved name for future brute forcing
	if e.Config.BruteForcing && e.Config.Recursive && (e.Config.MinForRecursive == 0) {
		// Do not send in the resolved root domain names
		if len(strings.Split(req.Name, ".")) != len(strings.Split(req.Domain, ".")) {
			e.bruteQueue.Append(req)
		}
	}

	// Queue the name and domain for future name alterations
	if e.Config.Alterations {
		e.altQueue.Append(req)
	}

	e.srcsLock.Lock()
	defer e.srcsLock.Unlock()

	for _, srv := range e.Sys.DataSources() {
		// Call DNSRequest for all web archive services
		if srv.Type() == requests.ARCHIVE && e.srcs.Has(srv.String()) {
			srv.DNSRequest(e.ctx, req)
		}
	}
}

func (e *Enumeration) checkSubdomain(req *requests.DNSRequest) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return
	}
	// It cannot have fewer labels than the root domain name
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return
	}
	// Do not further evaluate service subdomains
	if labels[1] == "_tcp" || labels[1] == "_udp" || labels[1] == "_tls" {
		return
	}

	sub := strings.Join(labels[1:], ".")

	for _, g := range e.Sys.GraphDatabases() {
		// CNAMEs are not a proper subdomain
		if g.IsCNAMENode(sub) {
			return
		}
	}

	r := &requests.DNSRequest{
		Name:   sub,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}
	times := e.timesForSubdomain(sub)

	e.Bus.Publish(requests.SubDiscoveredTopic, e.ctx, r, times)
	// Queue the proper subdomain for future brute forcing
	if e.Config.BruteForcing && e.Config.Recursive &&
		e.Config.MinForRecursive > 0 && e.Config.MinForRecursive == times {
		e.bruteQueue.Append(r)
	}
	// Check if the subdomain should be added to the markov model
	if e.Config.Alterations && times == 1 {
		e.markovModel.AddSubdomain(sub)
	}

	e.srcsLock.Lock()
	defer e.srcsLock.Unlock()

	// Let all the data sources know about the discovered proper subdomain
	for _, src := range e.Sys.DataSources() {
		if e.srcs.Has(src.String()) {
			src.SubdomainDiscovered(e.ctx, r, times)
		}
	}
}

func (e *Enumeration) timesForSubdomain(sub string) int {
	e.subLock.Lock()
	defer e.subLock.Unlock()

	times, found := e.subdomains[sub]
	if found {
		times++
	} else {
		times = 1
	}

	e.subdomains[sub] = times
	return times
}

func (e *Enumeration) reverseDNSSweep(addr string, cidr *net.IPNet) {
	// Does the address fall into a reserved address range?
	if info := checkForReservedAddress(addr); info != nil {
		return
	}

	var ips []net.IP
	// Get information about nearby IP addresses
	if e.Config.Active {
		ips = amassnet.CIDRSubset(cidr, addr, 500)
	} else {
		ips = amassnet.CIDRSubset(cidr, addr, 250)
	}

	for _, ip := range ips {
		a := ip.String()

		if e.filters.SweepAddrs.Duplicate(a) {
			continue
		}

		e.Sys.Config().SemMaxDNSQueries.Acquire(1)
		go e.reverseDNSQuery(a)
	}
}

func (e *Enumeration) reverseDNSQuery(ip string) {
	defer e.Sys.Config().SemMaxDNSQueries.Release(1)

	ptr, answer, err := e.Sys.Pool().Reverse(e.ctx, ip, resolvers.PriorityLow)
	if err != nil {
		return
	}
	// Check that the name discovered is in scope
	domain := e.Config.WhichDomain(answer)
	if domain == "" {
		return
	}

	go e.newResolvedName(&requests.DNSRequest{
		Name:   ptr,
		Domain: domain,
		Records: []requests.DNSAnswer{{
			Name: ptr,
			Type: 12,
			TTL:  0,
			Data: answer,
		}},
		Tag:    requests.DNS,
		Source: "Reverse DNS",
	})
}

func (e *Enumeration) hasCNAMERecord(req *requests.DNSRequest) bool {
	if len(req.Records) == 0 {
		return false
	}

	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeCNAME {
			return true
		}
	}

	return false
}
