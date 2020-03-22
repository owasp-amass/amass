// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/miekg/dns"
)

// AddressManager handles the investigation of addresses associated with newly resolved FQDNs.
type AddressManager struct {
	enum        *Enumeration
	revQueue    *queue.Queue
	resQueue    *queue.Queue
	revFilter   *stringset.StringFilter
	resFilter   *stringset.StringFilter
	sweepFilter *stringset.StringFilter
	asnLookup   chan *requests.AddrRequest
}

// NewAddressManager returns an initialized AddressManager.
func NewAddressManager(e *Enumeration) *AddressManager {
	am := &AddressManager{
		enum:        e,
		revQueue:    new(queue.Queue),
		resQueue:    new(queue.Queue),
		revFilter:   stringset.NewStringFilter(),
		resFilter:   stringset.NewStringFilter(),
		sweepFilter: stringset.NewStringFilter(),
		asnLookup:   make(chan *requests.AddrRequest),
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
			if (t == dns.TypeA || t == dns.TypeAAAA) && !r.resFilter.Duplicate(addr) {
				addreq := &requests.AddrRequest{
					Address: addr,
					Domain:  req.Domain,
				}

				go func(req *requests.AddrRequest) {
					r.asnLookup <- req
					r.resQueue.Append(req)
				}(addreq)
			}
		}
	}
}

// OutputNames implements the FQDNManager interface.
func (r *AddressManager) OutputNames(num int) []*requests.DNSRequest {
	for i := 0; ; i++ {
		if num >= 0 && i >= num {
			break
		}

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
	}

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

	go func() {
		r.asnLookup <- req
		r.revQueue.Append(req)
	}()
}

// Stop implements the FQDNManager interface.
func (r *AddressManager) Stop() error {
	r.revQueue = new(queue.Queue)
	r.resQueue = new(queue.Queue)
	r.revFilter = stringset.NewStringFilter()
	r.resFilter = stringset.NewStringFilter()
	r.sweepFilter = stringset.NewStringFilter()
	return nil
}

func (r *AddressManager) lookupASNInfo() {
	for {
		select {
		case <-r.enum.done:
			return
		case req := <-r.asnLookup:
			r.addToCachePlusDatabase(req)
		}
	}
}

func (r *AddressManager) addToCachePlusDatabase(req *requests.AddrRequest) {
	// Get the ASN / netblock information associated with this IP address
	asn := r.enum.netCache.AddrSearch(req.Address)
	if asn == nil {
		// Query the data sources for ASN information related to this IP address
		r.enum.asnRequestAllSources(&requests.ASNRequest{Address: req.Address})

		time.Sleep(3 * time.Second)
		asn = r.enum.netCache.AddrSearch(req.Address)

		for i := 0; asn == nil && i < 10; i++ {
			time.Sleep(time.Second)
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
			time.Sleep(time.Second)
			asn = r.enum.netCache.AddrSearch(req.Address)
		}

		if asn == nil {
			return
		}
	}

	if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
		go r.reverseDNSSweep(req.Address, cidr)
	}

	if r.enum.Config.Active && resolved {
		go r.enum.namesFromCertificates(req.Address)
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

		r.enum.Sys.Config().SemMaxDNSQueries.Acquire(1)
		go r.enum.reverseDNSQuery(a)
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

	e.Bus.Publish(requests.NameResolvedTopic, eventbus.PriorityLow,
		&requests.DNSRequest{
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
