// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

var (
	// Cache for the infrastructure data collected from online sources
	netLock  sync.Mutex
	netCache map[int]*core.ASNRequest
	// The reserved network address ranges
	reservedAddrRanges []*net.IPNet
	reservedCIDRs      = []string{
		"192.168.0.0/16",
		"172.16.0.0/12",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"169.254.0.0/16",
		"192.88.99.0/24",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.94.77.0/24",
		"192.94.78.0/24",
		"192.52.193.0/24",
		"192.12.109.0/24",
		"192.31.196.0/24",
		"192.0.0.0/29",
	}
)

// AddressService is the Service that handles all newly discovered IP addresses
// within the architecture. This is achieved by receiving all the NEWADDR events.
type AddressService struct {
	core.BaseService

	filter *utils.StringFilter
}

func init() {
	for _, cidr := range reservedCIDRs {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			reservedAddrRanges = append(reservedAddrRanges, ipnet)
		}
	}

	netCache = make(map[int]*core.ASNRequest)
}

// NewAddressService returns he object initialized, but not yet started.
func NewAddressService(config *core.Config, bus *eventbus.EventBus) *AddressService {
	as := &AddressService{filter: utils.NewStringFilter()}

	as.BaseService = *core.NewBaseService(as, "Address Service", config, bus)
	return as
}

// OnStart implements the Service interface
func (as *AddressService) OnStart() error {
	as.BaseService.OnStart()

	as.Bus().Subscribe(core.NewAddrTopic, as.SendAddrRequest)
	as.Bus().Subscribe(core.NewASNTopic, as.SendASNRequest)

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

	asn := ipSearch(req.Address)
	if asn == nil {
		return
	}
	if _, cidr, _ := net.ParseCIDR(asn.Prefix); cidr != nil {
		as.Bus().Publish(core.ReverseSweepTopic, req.Address, cidr)
	}
}

func (as *AddressService) performASNRequest(req *core.ASNRequest) {
	as.SetActive()
	as.updateConfigWithNetblocks(req)
	updateCache(req)
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

// IPRequest returns the ASN, CIDR and AS Description that contains the provided IP address.
func IPRequest(addr string, bus *eventbus.EventBus) (int, *net.IPNet, string, error) {
	if info := ipSearch(addr); info != nil {
		if _, ipnet, err := net.ParseCIDR(info.Prefix); err == nil {
			return info.ASN, ipnet, info.Description, nil
		}
	}

	asnchan := make(chan *core.ASNRequest, 10)
	f := func(req *core.ASNRequest) {
		asnchan <- req
	}

	bus.Subscribe(core.NewASNTopic, f)
	bus.Publish(core.IPToASNTopic, &core.ASNRequest{Address: addr})

	ip := net.ParseIP(addr)
	t := time.NewTimer(15 * time.Second)
loop:
	for {
		select {
		case <-t.C:
			break loop
		case a := <-asnchan:
			updateCache(a)
			for _, block := range a.Netblocks {
				if _, cidr, err := net.ParseCIDR(block); err == nil && cidr.Contains(ip) {
					break loop
				}
			}
		}
	}
	t.Stop()
	bus.Unsubscribe(core.NewASNTopic, f)

	if info := ipSearch(addr); info != nil {
		if _, ipnet, err := net.ParseCIDR(info.Prefix); err == nil {
			return info.ASN, ipnet, info.Description, nil
		}
	}
	return 0, nil, "", errors.New("Failed to obtain the IP information")
}

func updateCache(req *core.ASNRequest) {
	netLock.Lock()
	defer netLock.Unlock()

	if _, found := netCache[req.ASN]; !found {
		netCache[req.ASN] = req
		return
	}

	c := netCache[req.ASN]
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
	netCache[req.ASN] = c
}

func ipSearch(addr string) *core.ASNRequest {
	// Does the address fall into a reserved address range?
	if info := checkForReservedAddress(addr); info != nil {
		return info
	}

	netLock.Lock()
	defer netLock.Unlock()

	var a int
	var cidr *net.IPNet
	var desc string
	ip := net.ParseIP(addr)
	for asn, record := range netCache {
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

func checkForReservedAddress(addr string) *core.ASNRequest {
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
		return &core.ASNRequest{
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
