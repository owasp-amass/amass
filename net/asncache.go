// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package net

import (
	"net"
	"sync"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// ASNCache builds a cache of ASN and netblock information.
type ASNCache struct {
	sync.RWMutex
	cache map[int]*requests.ASNRequest
}

// NewASNCache returns an empty ASNCache for saving and search ASN and netblock information.
func NewASNCache() *ASNCache {
	return &ASNCache{cache: make(map[int]*requests.ASNRequest)}
}

// Update uses the saves the information in ASNRequest into the ASNCache.
func (c *ASNCache) Update(req *requests.ASNRequest) {
	c.Lock()
	defer c.Unlock()

	if _, found := c.cache[req.ASN]; !found {
		c.cache[req.ASN] = req
		if req.Netblocks == nil {
			req.Netblocks = stringset.New(req.Prefix)
		}
		return
	}

	as := c.cache[req.ASN]
	// This is additional information for an ASN entry
	if as.Prefix == "" && req.Prefix != "" {
		as.Prefix = req.Prefix
	}
	if as.CC == "" && req.CC != "" {
		as.CC = req.CC
	}
	if as.Registry == "" && req.Registry != "" {
		as.Registry = req.Registry
	}
	if as.AllocationDate.IsZero() && !req.AllocationDate.IsZero() {
		as.AllocationDate = req.AllocationDate
	}
	if as.Description == "" && req.Description != "" {
		as.Description = req.Description
	}
	if req.Netblocks == nil {
		as.Netblocks.Union(stringset.New(req.Prefix))
	} else {
		as.Netblocks.Union(req.Netblocks)
	}
}

// AddrSearch returns the cached ASN / netblock info that the addr parameter belongs in,
// or nil when not found in the cache.
func (c *ASNCache) AddrSearch(addr string) *requests.ASNRequest {
	// Does the address fall into a reserved address range?
	if yes, cidr := IsReservedAddress(addr); yes {
		return &requests.ASNRequest{
			Address:     addr,
			ASN:         0,
			Prefix:      cidr,
			Description: ReservedCIDRDescription,
			Tag:         requests.RIR,
			Source:      "RIR",
		}
	}

	c.RLock()
	defer c.RUnlock()

	var a int
	var cidr *net.IPNet
	var desc string
	ip := net.ParseIP(addr)
	for asn, record := range c.cache {
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
		Tag:         requests.RIR,
		Source:      "RIR",
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
