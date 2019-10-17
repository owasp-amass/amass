// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/graph"
	amassnet "github.com/OWASP/Amass/net"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	sf "github.com/OWASP/Amass/stringfilter"
)

// The reserved network address ranges
var reservedAddrRanges []*net.IPNet

func init() {
	for _, cidr := range amassnet.ReservedCIDRs {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			reservedAddrRanges = append(reservedAddrRanges, ipnet)
		}
	}
}

func (e *Enumeration) namesFromCertificates(addr string) {
	for _, name := range http.PullCertificateNames(addr, e.Config.Ports) {
		if n := strings.TrimSpace(name); n != "" {
			if domain := e.Config.WhichDomain(n); domain != "" {
				e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   n,
					Domain: domain,
					Tag:    requests.CERT,
					Source: "Active Cert",
				})
			}
		}
	}
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

func (e *Enumeration) updateConfigWithNetblocks(req *requests.ASNRequest) {
	filter := sf.NewStringFilter()

	for _, cidr := range e.Config.CIDRs {
		filter.Duplicate(cidr.String())
	}

	for block := range req.Netblocks {
		if filter.Duplicate(block) {
			continue
		}

		if _, ipnet, err := net.ParseCIDR(block); err == nil {
			e.Config.CIDRs = append(e.Config.CIDRs, ipnet)
		}
	}
}

func (e *Enumeration) updateASNCache(req *requests.ASNRequest) {
	e.netLock.Lock()
	defer e.netLock.Unlock()

	if _, found := e.netCache[req.ASN]; !found {
		e.netCache[req.ASN] = req
		return
	}

	c := e.netCache[req.ASN]
	// This is additional information for an ASN entry
	if c.Prefix == "" && req.Prefix != "" {
		c.Prefix = req.Prefix
	}
	if c.CC == "" && req.CC != "" {
		c.CC = req.CC
	}
	if c.Registry == "" && req.Registry != "" {
		c.Registry = req.Registry
	}
	if c.AllocationDate.IsZero() && !req.AllocationDate.IsZero() {
		c.AllocationDate = req.AllocationDate
	}
	if c.Description == "" && req.Description != "" {
		c.Description = req.Description
	}
	c.Netblocks.Union(req.Netblocks)
	e.netCache[req.ASN] = c
}

func (e *Enumeration) ipSearch(addr string) *requests.ASNRequest {
	// Does the address fall into a reserved address range?
	if info := checkForReservedAddress(addr); info != nil {
		return info
	}

	e.netLock.Lock()
	defer e.netLock.Unlock()

	var a int
	var cidr *net.IPNet
	var desc string
	ip := net.ParseIP(addr)
	for asn, record := range e.netCache {
		for netblock := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(netblock)
			if err != nil {
				continue
			}

			if ipnet.Contains(ip) {
				// Select the smallest CIDR
				if cidr != nil && compareCIDRSizes(cidr, ipnet) == 1 {
					continue
				}
				a = asn
				cidr = ipnet
				desc = record.Description
			}
		}
	}
	if cidr == nil {
		return nil
	}
	return &requests.ASNRequest{
		Address:     addr,
		ASN:         a,
		Prefix:      cidr.String(),
		Description: desc,
	}
}

func checkForReservedAddress(addr string) *requests.ASNRequest {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}

	var cidr string
	for _, block := range reservedAddrRanges {
		if block.Contains(ip) {
			cidr = block.String()
			break
		}
	}

	if cidr != "" {
		return &requests.ASNRequest{
			Address:     addr,
			Prefix:      cidr,
			Description: "Reserved Network Address Blocks",
		}
	}
	return nil
}

func compareCIDRSizes(first, second *net.IPNet) int {
	var result int

	s1, _ := first.Mask.Size()
	s2, _ := second.Mask.Size()
	if s1 > s2 {
		result = 1
	} else if s2 > s1 {
		result = -1
	}
	return result
}

// DNSQueriesPerSec returns the number of DNS queries the enumeration has performed per second.
func (e *Enumeration) DNSQueriesPerSec() int64 {
	e.perSecLock.Lock()
	defer e.perSecLock.Unlock()

	if sec := e.perSecLast.Sub(e.perSecFirst).Seconds(); sec > 0 {
		return e.perSec / int64(sec+1.0)
	}
	return 0
}

func (e *Enumeration) incQueriesPerSec(t time.Time) {
	go func(t time.Time) {
		e.perSecLock.Lock()
		defer e.perSecLock.Unlock()

		e.perSec++
		if t.After(e.perSecLast) {
			e.perSecLast = t
		}
	}(t)
}

func (e *Enumeration) clearPerSec() {
	e.perSecLock.Lock()
	defer e.perSecLock.Unlock()

	e.perSec = 0
	e.perSecFirst = time.Now()
	e.perSecLast = e.perSecLast
}

// DNSNamesRemaining returns the number of discovered DNS names yet to be handled by the enumeration.
func (e *Enumeration) DNSNamesRemaining() int64 {
	var remaining int

	for _, srv := range e.Sys.CoreServices() {
		switch srv.String() {
		case "DNS Service":
			remaining += srv.RequestLen()
		case "Brute Forcing":
			remaining += srv.RequestLen() * len(e.Config.Wordlist)
		}
	}

	return int64(remaining)
}

func (e *Enumeration) processOutput(wg *sync.WaitGroup) {
	defer wg.Done()

	curIdx := 0
	maxIdx := 7
	delays := []int{250, 500, 750, 1000, 1250, 1500, 1750, 2000}
loop:
	for {
		select {
		case <-e.done:
			break loop
		default:
			element, ok := e.outputQueue.Next()
			if !ok {
				if curIdx < maxIdx {
					curIdx++
				}
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				continue loop
			}
			curIdx = 0
			output := element.(*requests.Output)
			if !e.filters.Output.Duplicate(output.Name) {
				e.Output <- output
			}
		}
	}
	time.Sleep(5 * time.Second)
	// Handle all remaining elements on the queue
	for {
		element, ok := e.outputQueue.Next()
		if !ok {
			break
		}
		output := element.(*requests.Output)
		if !e.filters.Output.Duplicate(output.Name) {
			e.Output <- output
		}
	}
	close(e.Output)
}

func (e *Enumeration) checkForOutput(wg *sync.WaitGroup) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	defer wg.Done()

	for {
		select {
		case <-e.done:
			// Handle all remaining pieces of output
			e.queueNewGraphEntries(e.Config.UUID.String(), time.Millisecond)
			return
		case <-t.C:
			e.queueNewGraphEntries(e.Config.UUID.String(), 3*time.Second)
		}
	}
}

func (e *Enumeration) queueNewGraphEntries(uuid string, delay time.Duration) {
	for _, g := range e.Sys.GraphDatabases() {
		for _, o := range g.GetOutput(uuid, false) {
			if time.Now().After(o.Timestamp.Add(delay)) {
				g.MarkAsRead(&graph.DataOptsParams{
					UUID:   uuid,
					Name:   o.Name,
					Domain: o.Domain,
				})

				if e.Config.IsDomainInScope(o.Name) {
					e.outputQueue.Append(o)
				}
			}
		}
	}
}

func (e *Enumeration) sendOutput(o *requests.Output) {
	select {
	case <-e.done:
		return
	default:
		if e.Config.IsDomainInScope(o.Name) {
			e.outputQueue.Append(o)
		}
	}
}

func (e *Enumeration) refToDataManager() services.Service {
	for _, srv := range e.Sys.CoreServices() {
		if srv.String() == "Data Manager" {
			return srv
		}
	}
	return nil
}

func (e *Enumeration) queueLog(msg string) {
	e.logQueue.Append(msg)
}

func (e *Enumeration) writeLogs() {
	for {
		msg, ok := e.logQueue.Next()
		if !ok {
			break
		}

		if e.Config.Log != nil {
			e.Config.Log.Print(msg.(string))
		}
	}
}
