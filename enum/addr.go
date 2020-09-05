// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"net"
	"strings"

	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/miekg/dns"
)

type addrMsg struct {
	Req      *requests.AddrRequest
	Resolved bool
}

// AddressManager handles the investigation of addresses associated with newly resolved FQDNs.
type AddressManager struct {
	enum        *Enumeration
	queue       *queue.Queue
	filter      stringfilter.Filter
	sweepFilter stringfilter.Filter
}

// NewAddressManager returns an initialized AddressManager.
func NewAddressManager(e *Enumeration) *AddressManager {
	return &AddressManager{
		enum:        e,
		queue:       queue.NewQueue(),
		filter:      stringfilter.NewBloomFilter(1 << 16),
		sweepFilter: stringfilter.NewBloomFilter(1 << 16),
	}
}

// InputName implements the FQDNManager interface.
func (r *AddressManager) InputName(req *requests.DNSRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	// Clean up the newly discovered name and domain
	requests.SanitizeDNSRequest(req)
	// Add addresses that are relevant to the enumeration
	if !r.enum.hasCNAMERecord(req) && r.enum.hasARecords(req) {
		for _, rec := range req.Records {
			t := uint16(rec.Type)

			addr := strings.TrimSpace(rec.Data)
			if t == dns.TypeA || t == dns.TypeAAAA {
				r.addResolvedAddr(addr, req.Domain)
			}
		}
	}
}

func (r *AddressManager) addResolvedAddr(addr, domain string) {
	if r.filter.Duplicate(addr) {
		return
	}

	// Perform additional investigation of this address if
	// the associated domain is in scope
	if domain != "" && r.enum.Config.IsDomainInScope(domain) {
		r.queue.Append(&addrMsg{
			Req: &requests.AddrRequest{
				Address: addr,
				Domain:  domain,
			},
			Resolved: true,
		})
	}
}

// OutputNames implements the FQDNManager interface.
func (r *AddressManager) OutputNames(num int) []*requests.DNSRequest {
	return []*requests.DNSRequest{}
}

// InputAddress is unique to the AddressManager and uses the AddrRequest argument
// for reverse DNS queries in order to discover additional names in scope.
func (r *AddressManager) InputAddress(req *requests.AddrRequest) {
	if req == nil || req.Address == "" {
		return
	}

	// Have we already processed this address?
	if r.filter.Duplicate(req.Address) {
		return
	}

	// Perform additional investigation of this address if
	// the associated domain is in scope
	if req.Domain != "" && r.enum.Config.IsDomainInScope(req.Domain) {
		r.queue.Append(&addrMsg{
			Req:      req,
			Resolved: false,
		})
	}
}

// NameQueueLen implements the FQDNManager interface.
func (r *AddressManager) NameQueueLen() int {
	return 0
}

// OutputRequests implements the FQDNManager interface.
func (r *AddressManager) OutputRequests(num int) int {
	if num <= 0 {
		return 0
	}

	var count int
	element, ok := r.queue.Next()
	for ok {
		msg := element.(*addrMsg)
		go r.processAddress(msg.Req, msg.Resolved)

		count++
		if count >= num {
			break
		}

		element, ok = r.queue.Next()
	}

	return count
}

// RequestQueueLen implements the FQDNManager interface.
func (r *AddressManager) RequestQueueLen() int {
	return r.queue.Len()
}

// Stop implements the FQDNManager interface.
func (r *AddressManager) Stop() error {
	r.queue = queue.NewQueue()
	r.filter = stringfilter.NewBloomFilter(1 << 16)
	r.sweepFilter = stringfilter.NewBloomFilter(1 << 16)
	return nil
}

func (r *AddressManager) processAddress(req *requests.AddrRequest, resolved bool) {
	r.enum.asMgr.AddrRequest(r.enum.ctx, req)
	r.reverseDNSSweep(req.Address)

	if r.enum.Config.Active && resolved {
		r.enum.namesFromCertificates(req.Address)
	}
}

func (r *AddressManager) reverseDNSSweep(addr string) {
	// Does the address fall into a reserved address range?
	if yes, _ := amassnet.IsReservedAddress(addr); yes {
		return
	}

	var ips []net.IP
	cidr := r.enum.getAddrCIDR(addr)
	// Get information about nearby IP addresses
	if r.enum.Config.Active {
		ips = amassnet.CIDRSubset(cidr, addr, 500)
	} else {
		ips = amassnet.CIDRSubset(cidr, addr, 250)
	}

	for _, ip := range ips {
		a := ip.String()

		if r.sweepFilter.Duplicate(a) {
			continue
		}

		r.enum.Sys.PerformDNSQuery(r.enum.ctx)
		r.enum.reverseDNSQuery(a)
		r.enum.Sys.FinishedDNSQuery()
	}
}

func (e *Enumeration) getAddrCIDR(addr string) *net.IPNet {
	if r := e.asMgr.Cache.AddrSearch(addr); r != nil {
		if _, cidr, err := net.ParseCIDR(r.Prefix); err == nil {
			return cidr
		}
	}

	var mask net.IPMask
	ip := net.ParseIP(addr)
	if amassnet.IsIPv6(ip) {
		mask = net.CIDRMask(64, 128)
	} else {
		mask = net.CIDRMask(18, 32)
	}
	ip = ip.Mask(mask)

	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

func (e *Enumeration) reverseDNSQuery(ip string) {
	e.Bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, "Reverse DNS")

	ptr, answer, err := e.Sys.Pool().Reverse(e.ctx, ip, resolvers.PriorityLow)
	if err != nil {
		return
	}
	// Check that the name discovered is in scope
	domain := e.Config.WhichDomain(answer)
	if domain == "" {
		return
	}

	e.Bus.Publish(requests.NameResolvedTopic, eventbus.PriorityLow, &requests.DNSRequest{
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
