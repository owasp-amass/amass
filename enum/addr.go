// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/miekg/dns"
)

type asnChanMsg struct {
	Req      *requests.AddrRequest
	Resolved bool
}

// AddressManager handles the investigation of addresses associated with newly resolved FQDNs.
type AddressManager struct {
	enum        *Enumeration
	revQueue    *queue.Queue
	resQueue    *queue.Queue
	revFilter   stringfilter.Filter
	resFilter   stringfilter.Filter
	sweepFilter stringfilter.Filter
	asnReqQueue *queue.Queue
}

// NewAddressManager returns an initialized AddressManager.
func NewAddressManager(e *Enumeration) *AddressManager {
	am := &AddressManager{
		enum:        e,
		revQueue:    queue.NewQueue(),
		resQueue:    queue.NewQueue(),
		revFilter:   stringfilter.NewStringFilter(),
		resFilter:   stringfilter.NewStringFilter(),
		sweepFilter: stringfilter.NewBloomFilter(1 << 16),
		asnReqQueue: queue.NewQueue(),
	}

	go am.lookupASNInfo()
	return am
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
	if r.resFilter.Duplicate(addr) {
		return
	}

	r.asnReqQueue.Append(&asnChanMsg{
		Req: &requests.AddrRequest{
			Address: addr,
			Domain:  domain,
		},
		Resolved: true,
	})
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
	if r.revFilter.Duplicate(req.Address) {
		return
	}

	r.asnReqQueue.Append(&asnChanMsg{
		Req:      req,
		Resolved: false,
	})
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
	for count < num {
		resolved := true

		element, ok := r.resQueue.Next()
		if !ok {
			resolved = false
			element, ok = r.revQueue.Next()

			if !ok {
				break
			}
		}

		req := element.(*requests.AddrRequest)
		go r.processAddress(req, resolved)
		count++
	}

	return count
}

// RequestQueueLen implements the FQDNManager interface.
func (r *AddressManager) RequestQueueLen() int {
	return r.resQueue.Len() + r.revQueue.Len()
}

// Stop implements the FQDNManager interface.
func (r *AddressManager) Stop() error {
	r.revQueue = queue.NewQueue()
	r.resQueue = queue.NewQueue()
	r.revFilter = stringfilter.NewStringFilter()
	r.resFilter = stringfilter.NewStringFilter()
	r.sweepFilter = stringfilter.NewBloomFilter(1 << 16)
	return nil
}

func (r *AddressManager) lookupASNInfo() {
	for {
		select {
		case <-r.enum.done:
			return
		case <-r.asnReqQueue.Signal:
			e, found := r.asnReqQueue.Next()

			for found {
				msg := e.(*asnChanMsg)

				r.addToCachePlusDatabase(msg.Req)
				if msg.Resolved {
					r.resQueue.Append(msg.Req)
				} else {
					r.revQueue.Append(msg.Req)
				}

				e, found = r.asnReqQueue.Next()
			}
		}
	}
}

func (r *AddressManager) addToCachePlusDatabase(req *requests.AddrRequest) {
	// Get the ASN / netblock information associated with this IP address
	asn := r.enum.netCache.AddrSearch(req.Address)
	if asn == nil {
		wait := 3 * time.Second

		// Query the data sources for ASN information related to this IP address
		r.enum.asnRequestAllSources(&requests.ASNRequest{Address: req.Address})
		r.enum.Bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, "AddressManager")
		time.Sleep(wait)
		asn = r.enum.netCache.AddrSearch(req.Address)
		for i := 0; asn == nil && i < 10; i++ {
			r.enum.Bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, "AddressManager")
			time.Sleep(wait)
			asn = r.enum.netCache.AddrSearch(req.Address)
		}
	}

	if asn != nil {
		// Write the ASN information to the graph databases
		r.enum.dataMgr.ASNRequest(r.enum.ctx, asn)
	}
}

func (r *AddressManager) processAddress(req *requests.AddrRequest, resolved bool) {
	// Perform the reverse DNS sweep if the IP address is in scope
	if !r.enum.Config.IsDomainInScope(req.Domain) {
		return
	}

	// Get the ASN / netblock information associated with this IP address
	asn := r.enum.netCache.AddrSearch(req.Address)
	if asn == nil {
		for i := 0; asn == nil && i < 10; i++ {
			r.enum.Bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, "AddressManager")
			time.Sleep(3 * time.Second)
			asn = r.enum.netCache.AddrSearch(req.Address)
		}

		if asn == nil {
			return
		}
	}

	if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
		r.reverseDNSSweep(req.Address, cidr)
	}

	if r.enum.Config.Active && resolved {
		r.enum.namesFromCertificates(req.Address)
	}
}

func (r *AddressManager) reverseDNSSweep(addr string, cidr *net.IPNet) {
	// Does the address fall into a reserved address range?
	if yes, _ := amassnet.IsReservedAddress(addr); yes {
		return
	}

	var ips []net.IP
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

		r.enum.Sys.PerformDNSQuery(context.TODO())
		go r.enum.reverseDNSQuery(a)
	}
}

func (e *Enumeration) asnRequestAllSources(req *requests.ASNRequest) {
	// If data sources cannot assist in the next 2 minutes, the
	// request will be cancelled
	ctx, _ := context.WithTimeout(e.ctx, 30*time.Second)

	// All data sources will be employed, since this is required,
	// no matter what the user selects
	for _, src := range e.Sys.DataSources() {
		src.ASNRequest(ctx, req)
	}
}

func (e *Enumeration) reverseDNSQuery(ip string) {
	defer e.Sys.FinishedDNSQuery()

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
