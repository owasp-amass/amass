// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"net"
	"strconv"

	"github.com/OWASP/Amass/v3/filter"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
)

const (
	defaultSweepSize = 100
	activeSweepSize  = 200
	filterSize       = 20
)

// addrTask handles the investigation of addresses associated with newly resolved FQDNs.
type addrTask struct {
	enum        *Enumeration
	filter      filter.Filter
	sweepFilter filter.Filter
}

func newAddressTask(e *Enumeration) *addrTask {
	return &addrTask{
		enum:        e,
		filter:      filter.NewBloomFilter(1 << filterSize),
		sweepFilter: filter.NewBloomFilter(1 << filterSize),
	}
}

// Stop releases allocated resources by the addrTask.
func (r *addrTask) Stop() {
	r.filter = filter.NewBloomFilter(1)
	r.sweepFilter = filter.NewBloomFilter(1)
}

// Process implements the pipeline Task interface.
func (r *addrTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	req, ok := data.(*requests.AddrRequest)
	if !ok {
		return data, nil
	}
	if req == nil || !req.Valid() {
		return nil, nil
	}
	// Do not submit addresses after already processing them as in-scope
	if r.filter.Has(req.Address + strconv.FormatBool(true)) {
		return nil, nil
	}
	if r.filter.Duplicate(req.Address + strconv.FormatBool(req.InScope)) {
		return nil, nil
	}

	if req.InScope {
		r.sendAddr(ctx, req, tp)
		// Does the address fall into a reserved address range?
		if yes, _ := amassnet.IsReservedAddress(req.Address); !yes {
			// Generate the additional addresses to sweep across
			r.sweepAddrs(ctx, req, tp)
		}
	}
	return nil, nil
}

func (r *addrTask) sendAddr(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	pipeline.SendData(ctx, "store", &requests.AddrRequest{
		Address: req.Address,
		InScope: req.InScope,
		Domain:  req.Domain,
		Tag:     req.Tag,
		Source:  req.Source,
	}, tp)
}

func (r *addrTask) sweepAddrs(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	size := defaultSweepSize
	if r.enum.Config.Active {
		size = activeSweepSize
	}

	cidr := r.addrCIDR(req.Address)
	// Get information about nearby IP addresses
	ips := amassnet.CIDRSubset(cidr, req.Address, size)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if a := ip.String(); !r.sweepFilter.Duplicate(a) {
			pipeline.SendData(ctx, "dns", &requests.AddrRequest{
				Address: a,
				Domain:  req.Domain,
				Tag:     req.Tag,
				Source:  req.Source,
			}, tp)
		}
	}
}

func (r *addrTask) addrCIDR(addr string) *net.IPNet {
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
