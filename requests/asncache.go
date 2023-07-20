// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package requests

import (
	"net"
	"strings"
	"sync"

	"github.com/caffix/stringset"
	"github.com/yl2chen/cidranger"
)

var reservedCIDRs = []string{
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

// ASNCache builds a cache of ASN and netblock information.
type ASNCache struct {
	sync.RWMutex
	cache  map[int]*ASNRequest
	ranger cidranger.Ranger
}

type cacheRangerEntry struct {
	IPNet net.IPNet
	Data  *ASNRequest
}

// The reserved network address ranges
var reservedAddrRanges []*net.IPNet

func init() {
	for _, cidr := range reservedCIDRs {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			reservedAddrRanges = append(reservedAddrRanges, ipnet)
		}
	}
}

func (e *cacheRangerEntry) Network() net.IPNet {
	return e.IPNet
}

// NewASNCache returns an empty ASNCache for saving and searching ASN and netblock information.
func NewASNCache() *ASNCache {
	return &ASNCache{
		cache:  make(map[int]*ASNRequest),
		ranger: cidranger.NewPCTrieRanger(),
	}
}

// Update saves the information in ASNRequest into the ASNCache.
func (c *ASNCache) Update(req *ASNRequest) {
	c.Lock()
	defer c.Unlock()

	as, found := c.cache[req.ASN]
	if !found {
		c.cache[req.ASN] = req
		if len(req.Netblocks) == 0 {
			req.Netblocks = []string{req.Prefix}
		}
		return
	}

	// This is additional information for an ASN entry
	if as.CC == "" && req.CC != "" {
		as.CC = req.CC
	}
	if as.Registry == "" && req.Registry != "" {
		as.Registry = req.Registry
	}
	if as.AllocationDate.IsZero() && !req.AllocationDate.IsZero() {
		as.AllocationDate = req.AllocationDate
	}
	if len(as.Description) < len(req.Description) {
		as.Description = req.Description
	}

	// Add new CIDR ranges to cached netblocks
	for _, cidr := range append([]string{req.Prefix}, req.Netblocks...) {
		var known bool

		for _, prefix := range as.Netblocks {
			if prefix == cidr {
				known = true
				break
			}
		}

		if !known {
			as.Netblocks = append(as.Netblocks, cidr)
		}
	}
}

// DescriptionSearch matches the provided string against description fields in the cache and
// returns the ASN / netblock info for matching entries.
func (c *ASNCache) DescriptionSearch(s string) []*ASNRequest {
	c.Lock()
	defer c.Unlock()

	var matches []*ASNRequest
	for _, entry := range c.cache {
		if strings.Contains(entry.Description, s) {
			matches = append(matches, entry)
		}
	}
	return matches
}

// ASNSearch returns the cached ASN / netblock info associated with the provided asn parameter,
// or nil when not found in the cache.
func (c *ASNCache) ASNSearch(asn int) *ASNRequest {
	c.Lock()
	defer c.Unlock()

	return c.cache[asn]
}

// AddrSearch returns the cached ASN / netblock info that the addr parameter belongs in,
// or nil when not found in the cache.
func (c *ASNCache) AddrSearch(addr string) *ASNRequest {
	c.Lock()
	defer c.Unlock()

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}

	// Does the address fall into a reserved address ranges?
	if yes, cidr := isReservedAddress(addr); yes {
		return &ASNRequest{
			Address:     addr,
			ASN:         0,
			Prefix:      cidr,
			Description: "Reserved Network Address Blocks",
		}
	}

	entry := c.searchRangerData(ip)
	if entry == nil {
		c.rawData2Ranger(ip)

		entry = c.searchRangerData(ip)
		if entry == nil {
			return nil
		}
	}

	prefix := entry.IPNet.String()
	netblocks := stringset.New(prefix)
	defer netblocks.Close()

	netblocks.InsertMany(entry.Data.Netblocks...)
	return &ASNRequest{
		Address:     addr,
		ASN:         entry.Data.ASN,
		CC:          entry.Data.CC,
		Prefix:      prefix,
		Netblocks:   netblocks.Slice(),
		Description: entry.Data.Description,
	}
}

func (c *ASNCache) searchRangerData(ip net.IP) *cacheRangerEntry {
	if entries, err := c.ranger.ContainingNetworks(ip); err == nil {
		for _, e := range entries {
			if entry, ok := e.(*cacheRangerEntry); ok {
				return entry
			}
		}
	}
	return nil
}

func (c *ASNCache) rawData2Ranger(ip net.IP) {
	var cidr *net.IPNet
	var data *ASNRequest

	for _, record := range c.cache {
		for _, netblock := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(netblock)
			if err != nil {
				continue
			}
			if ones, _ := ipnet.Mask.Size(); ones == 0 {
				continue
			}

			if ipnet.Contains(ip) {
				// Select the smallest CIDR
				if cidr != nil && compareCIDRSizes(cidr, ipnet) == 1 {
					continue
				}
				data = record
				cidr = ipnet
			}
		}
	}

	if cidr != nil {
		_ = c.ranger.Insert(&cacheRangerEntry{
			IPNet: *cidr,
			Data:  data,
		})
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

func isReservedAddress(addr string) (bool, string) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false, ""
	}

	var cidr string
	for _, block := range reservedAddrRanges {
		if block.Contains(ip) {
			cidr = block.String()
			break
		}
	}

	if cidr != "" {
		return true, cidr
	}
	return false, ""
}
