// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"net"
	"strings"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/miekg/dns"
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

func (e *Enumeration) newAddress(req *requests.AddrRequest) {
	if req == nil || req.Address == "" {
		return
	}

	// Is this address relevant to the enumeration?
	if !e.hasAddress(req.Address) {
		return
	}

	// Have we already processed this address?
	if e.filters.NewAddrs.Duplicate(req.Address) {
		return
	}

	e.netQueue.Append(req)
}

func (e *Enumeration) processAddresses() {
	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}

	checkSoon := new(queue.Queue)
	check := time.NewTicker(30 * time.Second)
	defer check.Stop()
loop:
	for {
		select {
		case <-e.done:
			return
		case <-check.C:
			for {
				element, ok := checkSoon.Next()
				if !ok {
					break
				}

				e.netQueue.Append(element)
			}
		default:
			element, ok := e.netQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			curIdx = 0
			req := element.(*requests.AddrRequest)
			if req.Address == "" {
				continue loop
			}

			asn := e.ipSearch(req.Address)
			if asn == nil {
				// Query the data sources for ASN information related to this IP address
				e.asnRequestAllSources(&requests.ASNRequest{Address: req.Address})
				time.Sleep(10 * time.Second)
				checkSoon.Append(req)
				continue loop
			}

			// Write the ASN information to the graph databases
			e.dataMgr.ASNRequest(e.ctx, asn)

			// Perform the reverse DNS sweep if the IP address is in scope
			if e.Config.IsDomainInScope(req.Domain) {
				if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
					go e.reverseDNSSweep(req.Address, cidr)
				}

				if e.Config.Active {
					go e.namesFromCertificates(req.Address)
				}
			}
		}
	}
}

func (e *Enumeration) asnRequestAllSources(req *requests.ASNRequest) {
	e.srcsLock.Lock()
	defer e.srcsLock.Unlock()

	for _, src := range e.Sys.DataSources() {
		if e.srcs.Has(src.String()) {
			src.ASNRequest(e.ctx, req)
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
		Tag:         requests.NONE,
		Source:      "NONE",
	}
}

func (e *Enumeration) addAddress(addr string) {
	e.addrsLock.Lock()
	defer e.addrsLock.Unlock()

	e.addrs.Insert(strings.TrimSpace(addr))
}

func (e *Enumeration) hasAddress(addr string) bool {
	e.addrsLock.Lock()
	defer e.addrsLock.Unlock()

	return e.addrs.Has(strings.TrimSpace(addr))
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
			Tag:         requests.NONE,
			Source:      "NONE",
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

func (e *Enumeration) hasARecords(req *requests.DNSRequest) bool {
	if len(req.Records) == 0 {
		return false
	}

	var found bool
	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeA || t == dns.TypeAAAA {
			found = true
		}
	}

	return found
}
