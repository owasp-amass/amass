// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"net"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/caffix/pipeline"
)

const (
	defaultSweepSize = 100
	activeSweepSize  = 200
)

// addrTask handles the investigation of addresses associated with newly resolved FQDNs.
type addrTask struct {
	enum        *Enumeration
	filter      stringfilter.Filter
	sweepFilter stringfilter.Filter
}

func newAddressTask(e *Enumeration) *addrTask {
	return &addrTask{
		enum:        e,
		filter:      stringfilter.NewBloomFilter(1 << 16),
		sweepFilter: stringfilter.NewBloomFilter(1 << 16),
	}
}

// Stop releases allocated resources by the AddressTask.
func (r *addrTask) Stop() error {
	r.filter = stringfilter.NewBloomFilter(1 << 16)
	r.sweepFilter = stringfilter.NewBloomFilter(1 << 16)
	return nil
}

// Process implements the pipeline Task interface.
func (r *addrTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	req, ok := data.(*requests.AddrRequest)
	if !ok {
		return data, nil
	}
	if req == nil || !req.Valid() {
		fmt.Printf("%s was dropped with '%s' domain from source %s", req.Address, req.Domain, req.Source)
		return nil, nil
	}
	// Does the address fall into a reserved address range?
	if yes, _ := amassnet.IsReservedAddress(req.Address); yes {
		return nil, nil
	}
	// Have we already processed this address?
	if r.filter.Duplicate(req.Address) {
		return nil, nil
	}
	// Perform additional investigation of this address if
	// the associated domain is in scope
	if !r.enum.Config.IsDomainInScope(req.Domain) {
		return nil, nil
	}
	// Generate the additional addresses to sweep across
	r.genSweepAddrs(ctx, req, tp)
	return data, nil
}

func (r *addrTask) genSweepAddrs(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	size := defaultSweepSize
	if r.enum.Config.Active {
		size = activeSweepSize
	}

	cidr := r.getAddrCIDR(req.Address)
	// Get information about nearby IP addresses
	ips := amassnet.CIDRSubset(cidr, req.Address, size)

	for _, ip := range ips {
		if a := ip.String(); !r.sweepFilter.Duplicate(a) {
			go pipeline.SendData(ctx, "dns", &requests.AddrRequest{
				Address: a,
				Domain:  req.Domain,
				Tag:     req.Tag,
				Source:  req.Source,
			}, tp)
		}
	}
}

func (r *addrTask) getAddrCIDR(addr string) *net.IPNet {
	if asn := r.enum.Sys.Cache().AddrSearch(addr); asn != nil {
		if _, cidr, err := net.ParseCIDR(asn.Prefix); err == nil {
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
