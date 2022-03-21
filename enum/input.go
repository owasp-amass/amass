// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/service"
	bf "github.com/tylertreat/BoomFilters"
)

const (
	waitForDuration  = 10 * time.Second
	defaultSweepSize = 100
	activeSweepSize  = 200
)

// enumSource handles the filtering and release of new Data in the enumeration.
type enumSource struct {
	enum        *Enumeration
	queue       queue.Queue
	dups        queue.Queue
	sweeps      queue.Queue
	filter      *bf.StableBloomFilter
	sweepFilter *bf.StableBloomFilter
	subre       *regexp.Regexp
	done        chan struct{}
	doneOnce    sync.Once
	release     chan struct{}
	inputsig    chan uint32
	lastFill    time.Time
	max         int
	countLock   sync.Mutex
	count       uint32
}

// newEnumSource returns an initialized input source for the enumeration pipeline.
func newEnumSource(e *Enumeration) *enumSource {
	qps := e.Sys.Resolvers().QPS()
	if qps < 1000 {
		qps = 1000
	}

	r := &enumSource{
		enum:        e,
		queue:       queue.NewQueue(),
		dups:        queue.NewQueue(),
		sweeps:      queue.NewQueue(),
		filter:      bf.NewDefaultStableBloomFilter(1000000, 0.01),
		sweepFilter: bf.NewDefaultStableBloomFilter(100000, 0.01),
		subre:       dns.AnySubdomainRegex(),
		done:        make(chan struct{}),
		release:     make(chan struct{}, qps),
		inputsig:    make(chan uint32, qps*2),
		max:         qps,
	}
	// Monitor the enumeration for completion or termination
	go func() {
		select {
		case <-r.enum.ctx.Done():
			r.markDone()
		case <-r.enum.done:
			r.markDone()
		}
	}()

	for _, src := range e.srcs {
		go r.monitorDataSrcOutput(src)
	}

	for i := 0; i < qps; i++ {
		r.release <- struct{}{}
	}

	go r.processDupNames()
	return r
}

func (r *enumSource) Stop() {
	r.markDone()
	r.queue.Process(func(e interface{}) {})
	r.dups.Process(func(e interface{}) {})
	r.sweeps.Process(func(e interface{}) {})
	r.filter.Reset()
	r.sweepFilter.Reset()
}

func (r *enumSource) markDone() {
	r.doneOnce.Do(func() {
		close(r.done)
	})
}

func (r *enumSource) dataSourceName(req *requests.DNSRequest) {
	if req != nil && req.Name != "" && r.enum.Config.IsDomainInScope(req.Name) {
		r.pipelineData(r.enum.ctx, req, nil)
	}
}

func (r *enumSource) dataSourceAddr(req *requests.AddrRequest) {
	if req != nil && req.Address != "" {
		r.pipelineData(r.enum.ctx, req, nil)
	}
}

func (r *enumSource) pipelineData(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) {
	select {
	case <-ctx.Done():
		return
	case <-r.done:
		return
	default:
	}

	switch v := data.(type) {
	case *requests.DNSRequest:
		if v != nil && v.Valid() {
			go r.newName(v)
		}
	case *requests.AddrRequest:
		if v != nil && v.Valid() {
			go r.newAddr(ctx, v, tp)
		}
	}
}

func (r *enumSource) newName(req *requests.DNSRequest) {
	// Clean up the newly discovered name and domain
	requests.SanitizeDNSRequest(req)
	// Check that the name is valid
	if r.subre.FindString(req.Name) != req.Name {
		return
	}
	// Do not further evaluate service subdomains
	for _, label := range strings.Split(req.Name, ".") {
		l := strings.ToLower(label)

		if l == "_tcp" || l == "_udp" || l == "_tls" {
			return
		}
	}
	if r.accept(req.Name, req.Tag, req.Source, true) {
		r.queue.Append(req)
	}
}

func (r *enumSource) newAddr(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	if !req.InScope || tp == nil || !r.accept(req.Address, req.Tag, req.Source, false) {
		return
	}

	r.sendAddr(ctx, req, tp)
	// Does the address fall into a reserved address range?
	if yes, _ := amassnet.IsReservedAddress(req.Address); !yes {
		// Queue the request for later use in reverse DNS sweeps
		r.sweeps.Append(req)
	}
}

func (r *enumSource) sendAddr(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	pipeline.SendData(ctx, "store", &requests.AddrRequest{
		Address: req.Address,
		InScope: req.InScope,
		Domain:  req.Domain,
		Tag:     req.Tag,
		Source:  req.Source,
	}, tp)
}

func (r *enumSource) accept(s, tag, source string, name bool) bool {
	trusted := requests.TrustedTag(tag)
	// Do not submit names from untrusted sources, after already receiving the name
	// from a trusted source
	if !trusted && r.filter.Test([]byte(s+strconv.FormatBool(true))) {
		if name {
			r.dups.Append(&requests.DNSRequest{
				Name:   s,
				Tag:    tag,
				Source: source,
			})
		}
		return false
	}
	// At most, a FQDN will be accepted from an untrusted source first, and then
	// reconsidered from a trusted data source
	if r.filter.Test([]byte(s + strconv.FormatBool(trusted))) {
		if name {
			r.dups.Append(&requests.DNSRequest{
				Name:   s,
				Tag:    tag,
				Source: source,
			})
		}
		return false
	}

	r.filter.Add([]byte(s + strconv.FormatBool(trusted)))
	return true
}

// Next implements the pipeline InputSource interface.
func (r *enumSource) Next(ctx context.Context) bool {
	t := time.NewTimer(waitForDuration)
	defer t.Stop()
	check := time.NewTimer(10 * time.Millisecond)
	defer check.Stop()

	for {
		select {
		case <-r.done:
			return false
		case <-ctx.Done():
			r.markDone()
			return false
		case <-t.C:
			r.markDone()
			return false
		case <-r.queue.Signal():
			r.fillQueue()
			return true
		case <-check.C:
			r.fillQueue()
			check.Reset(500 * time.Millisecond)
		}
	}
}

// Data implements the pipeline InputSource interface.
func (r *enumSource) Data() pipeline.Data {
	var data pipeline.Data

	if element, ok := r.queue.Next(); ok {
		data = element.(pipeline.Data)
		// Attempt to signal that new input was added to the pipeline
		select {
		case r.inputsig <- r.incrementCount():
		default:
		}
	}
	return data
}

func (r *enumSource) getCount() uint32 {
	r.countLock.Lock()
	defer r.countLock.Unlock()

	return r.count
}

func (r *enumSource) incrementCount() uint32 {
	r.countLock.Lock()
	defer r.countLock.Unlock()

	if r.count < (1<<32)-1 {
		r.count++
		return r.count
	}

	r.count = 0
	return 0
}

// Error implements the pipeline InputSource interface.
func (r *enumSource) Error() error {
	return nil
}

func (r *enumSource) fillQueue() {
	if time.Since(r.lastFill) < 500*time.Millisecond {
		return
	}
	if unfilled := r.max - r.queue.Len(); unfilled > 0 {
		fill := unfilled - len(r.release)

		if fill > 0 {
			r.releaseOutput(fill)
		}
		if remaining := unfilled - fill; remaining > 0 {
			go func(num int) { _ = r.requestSweeps(num) }(remaining)
		}
	}
	r.lastFill = time.Now()
}

func (r *enumSource) releaseOutput(num int) {
	for i := 0; i < num; i++ {
		select {
		case r.release <- struct{}{}:
		default:
		}
	}
}

func (r *enumSource) monitorDataSrcOutput(srv service.Service) {
	for {
		select {
		case <-r.done:
			return
		case <-srv.Done():
			return
		case in := <-srv.Output():
			select {
			case <-r.done:
				return
			case <-srv.Done():
				return
			case <-r.release:
			}

			switch req := in.(type) {
			case *requests.DNSRequest:
				r.newName(req)
			case *requests.AddrRequest:
				r.dataSourceAddr(req)
			}
		}
	}
}

func (r *enumSource) requestSweeps(num int) int {
	var count int

	for count < num {
		if e, ok := r.sweeps.Next(); ok {
			// Generate the additional addresses to sweep across
			count += r.sweepAddrs(r.enum.ctx, e.(*requests.AddrRequest))
		}
	}
	return count
}

func (r *enumSource) sweepAddrs(ctx context.Context, req *requests.AddrRequest) int {
	size := defaultSweepSize
	if r.enum.Config.Active {
		size = activeSweepSize
	}

	cidr := r.addrCIDR(req.Address)
	// Get information about nearby IP addresses
	ips := amassnet.CIDRSubset(cidr, req.Address, size)

	var count int
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return count
		default:
		}

		if a := ip.String(); !r.sweepFilter.TestAndAdd([]byte(a)) {
			count++
			r.queue.Append(&requests.AddrRequest{
				Address: a,
				Domain:  req.Domain,
				Tag:     req.Tag,
				Source:  req.Source,
			})
		}
	}
	return count
}

func (r *enumSource) addrCIDR(addr string) *net.IPNet {
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

// This goroutine ensures that duplicate names from other sources are shown in the Graph.
func (r *enumSource) processDupNames() {
	countdown := r.max * 2
	var inc uint32 = uint32(r.max) * 2
	var highest uint32 = (1 << 32) - 1

	type altsource struct {
		Name      string
		Source    string
		Tag       string
		Min       uint32
		Countdown int
	}

	var pending []*altsource
	each := func(element interface{}) {
		if req := element.(*requests.DNSRequest); req.Tag != requests.BRUTE && req.Tag != requests.ALT {
			min := r.getCount()
			if highest-min < inc {
				min = 0
			}
			pending = append(pending, &altsource{
				Name:      req.Name,
				Source:    req.Source,
				Tag:       req.Tag,
				Min:       min,
				Countdown: countdown,
			})
		}
	}

	uuid := r.enum.Config.UUID.String()
loop:
	for {
		select {
		case <-r.done:
			break loop
		case <-r.dups.Signal():
			r.dups.Process(each)
		case num := <-r.inputsig:
			var removed int

			for i, a := range pending {
				if i >= len(pending)-removed {
					break
				}
				if a.Min >= num {
					a.Countdown--
				}
				if a.Countdown <= 0 {
					if _, err := r.enum.graph.ReadNode(r.enum.ctx, a.Name, "fqdn"); err == nil {
						_, _ = r.enum.graph.UpsertFQDN(r.enum.ctx, a.Name, a.Source, uuid)
					}
					// Remove the element
					removed++
					pending[i] = pending[len(pending)-removed]
				}
			}
			if removed > 0 {
				pending = pending[:len(pending)-removed]
			}
		}
	}
	// Last attempt to update the sources information
	r.dups.Process(each)
	for _, a := range pending {
		if _, err := r.enum.graph.ReadNode(r.enum.ctx, a.Name, "fqdn"); err == nil {
			_, _ = r.enum.graph.UpsertFQDN(r.enum.ctx, a.Name, a.Source, uuid)
		}
	}
}
