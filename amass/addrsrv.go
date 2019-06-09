// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// AddressService is the Service that handles all newly discovered IP addresses
// within the architecture. This is achieved by receiving all the NEWADDR events.
type AddressService struct {
	core.BaseService

	filter *utils.StringFilter
	// The private network address ranges
	private192 *net.IPNet
	private172 *net.IPNet
	private10  *net.IPNet
	// Cache for the infrastructure data collected from online sources
	netLock  sync.Mutex
	netCache map[int]*core.ASNRequest
}

// NewAddressService returns he object initialized, but not yet started.
func NewAddressService(config *core.Config, bus *core.EventBus) *AddressService {
	as := &AddressService{
		filter:   utils.NewStringFilter(),
		netCache: make(map[int]*core.ASNRequest),
	}

	_, as.private192, _ = net.ParseCIDR("192.168.0.0/16")
	_, as.private172, _ = net.ParseCIDR("172.16.0.0/12")
	_, as.private10, _ = net.ParseCIDR("10.0.0.0/8")

	as.BaseService = *core.NewBaseService(as, "Address Service", config, bus)
	return as
}

// OnStart implements the Service interface
func (as *AddressService) OnStart() error {
	as.BaseService.OnStart()

	as.Bus().Subscribe(core.NewAddrTopic, as.SendAddrRequest)
	as.Bus().Subscribe(core.NewASNTopic, as.SendASNRequest)
	as.Bus().Subscribe(core.IPRequestTopic, as.performIPRequest)

	// Put in requests for all the ASNs specified in the configuration
	for _, asn := range as.Config().ASNs {
		as.Bus().Publish(core.IPToASNTopic, &core.ASNRequest{ASN: asn})
	}
	// Give the data sources some time to obtain the results
	time.Sleep(2 * time.Second)
	go as.processRequests()
	return nil
}

func (as *AddressService) processRequests() {
	for {
		select {
		case <-as.PauseChan():
			<-as.ResumeChan()
		case <-as.Quit():
			return
		case addr := <-as.AddrRequestChan():
			go as.performAddrRequest(addr)
		case asn := <-as.ASNRequestChan():
			go as.performASNRequest(asn)
		case <-as.DNSRequestChan():
		case <-as.WhoisRequestChan():
		}
	}
}

func (as *AddressService) performAddrRequest(req *core.AddrRequest) {
	if req == nil || req.Address == "" {
		return
	}
	as.SetActive()

	if as.filter.Duplicate(req.Address) {
		return
	}
	as.Bus().Publish(core.ActiveCertTopic, req)

	asn := as.ipSearch(req.Address)
	if asn == nil {
		return
	}
	if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
		as.Bus().Publish(core.ReverseSweepTopic, req.Address, cidr)
	}
}

func (as *AddressService) performASNRequest(req *core.ASNRequest) {
	as.netLock.Lock()
	defer as.netLock.Unlock()

	as.SetActive()
	as.updateConfigWithNetblocks(req)
	if _, found := as.netCache[req.ASN]; !found {
		as.netCache[req.ASN] = req
		return
	}

	c := as.netCache[req.ASN]
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
	c.Netblocks = utils.UniqueAppend(c.Netblocks, req.Netblocks...)
}

func (as *AddressService) updateConfigWithNetblocks(req *core.ASNRequest) {
	var match bool
	for _, asn := range as.Config().ASNs {
		if req.ASN == asn {
			match = true
			break
		}
	}
	if !match {
		return
	}

	filter := utils.NewStringFilter()
	for _, cidr := range as.Config().CIDRs {
		filter.Duplicate(cidr.String())
	}

	for _, block := range req.Netblocks {
		if filter.Duplicate(block) {
			continue
		}

		if _, ipnet, err := net.ParseCIDR(block); err == nil {
			as.Config().CIDRs = append(as.Config().CIDRs, ipnet)
		}
	}
}

func (as *AddressService) performIPRequest(req *core.ASNRequest) {
	as.SetActive()

	if req.Address != "" {
		// Does the address fall into a private network range?
		if asn := as.checkForPrivateAddress(req.Address); asn != nil {
			as.Bus().Publish(core.IPInfoTopic, asn)
			return
		}
		// Is the data already available in the cache?
		if asn := as.ipSearch(req.Address); asn != nil {
			as.Bus().Publish(core.IPInfoTopic, asn)
			return
		}
		// Ask the data sources for the ASN information
		as.Bus().Publish(core.IPToASNTopic, req)
		// Wait for the results to hit the cache
		for i := 0; i < 10; i++ {
			time.Sleep(time.Second)
			if asn := as.ipSearch(req.Address); asn != nil {
				as.Bus().Publish(core.IPInfoTopic, asn)
				return
			}
		}
	} else if req.ASN > 0 {
		if asn, found := as.netCache[req.ASN]; found {
			as.Bus().Publish(core.IPInfoTopic, asn)
			return
		}

		as.Bus().Publish(core.IPToASNTopic, req)
		// Wait for the results to hit the cache
		for i := 0; i < 10; i++ {
			time.Sleep(time.Second)
			as.netLock.Lock()
			if asn, found := as.netCache[req.ASN]; found {
				as.Bus().Publish(core.IPInfoTopic, asn)
				return
			}
		}
	}
}

func (as *AddressService) ipSearch(addr string) *core.ASNRequest {
	as.netLock.Lock()
	defer as.netLock.Unlock()

	var a int
	var cidr *net.IPNet
	var desc string
	ip := net.ParseIP(addr)
	for asn, record := range as.netCache {
		for _, netblock := range record.Netblocks {
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
	return &core.ASNRequest{
		Address:     addr,
		ASN:         a,
		Prefix:      cidr.String(),
		Description: desc,
	}
}

func (as *AddressService) checkForPrivateAddress(addr string) *core.ASNRequest {
	var n string
	ip := net.ParseIP(addr)
	desc := "Private Networks"

	if as.private192.Contains(ip) {
		n = as.private192.String()
	} else if as.private172.Contains(ip) {
		n = as.private172.String()
	} else if as.private10.Contains(ip) {
		n = as.private10.String()
	}

	if n == "" {
		return nil
	}
	return &core.ASNRequest{
		Address:     addr,
		Prefix:      n,
		Description: desc,
	}
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

// IPRequest returns the ASN, CIDR and AS Description that contains the provided IP address.
func IPRequest(addr string, bus *core.EventBus) (int, *net.IPNet, string, error) {
	asnchan := make(chan *core.ASNRequest, 1)
	f := func(req *core.ASNRequest) {
		if req.Address == addr {
			asnchan <- req
		}
	}

	bus.Subscribe(core.IPInfoTopic, f)
	defer bus.Unsubscribe(core.IPInfoTopic, f)
	bus.Publish(core.IPRequestTopic, &core.ASNRequest{Address: addr})

	var a int
	var cidr *net.IPNet
	var desc string
	t := time.NewTimer(5 * time.Second)
	select {
	case <-t.C:
	case asn := <-asnchan:
		a = asn.ASN
		_, cidr, _ = net.ParseCIDR(asn.Prefix)
		desc = asn.Description
	}

	if cidr == nil {
		return 0, nil, "", errors.New("Failed to obtain the IP information")
	}
	return a, cidr, desc, nil
}
