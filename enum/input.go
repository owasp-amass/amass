// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/filter"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
)

const (
	minWaitForData   = 15 * time.Second
	maxWaitForData   = 30 * time.Second
	defaultSweepSize = 100
	activeSweepSize  = 200
)

// enumSource handles the filtering and release of new Data in the enumeration.
type enumSource struct {
	sync.Mutex
	enum        *Enumeration
	queue       queue.Queue
	dups        queue.Queue
	sweeps      queue.Queue
	filter      filter.Filter
	sweepFilter filter.Filter
	subre       *regexp.Regexp
	count       int64
	done        chan struct{}
	maxSlots    int
	timeout     time.Duration
}

// newEnumSource returns an initialized input source for the enumeration pipeline.
func newEnumSource(e *Enumeration, slots int) *enumSource {
	r := &enumSource{
		enum:        e,
		queue:       queue.NewQueue(),
		dups:        queue.NewQueue(),
		sweeps:      queue.NewQueue(),
		filter:      filter.NewBloomFilter(filterMaxSize),
		sweepFilter: filter.NewBloomFilter(filterMaxSize),
		subre:       dns.AnySubdomainRegex(),
		done:        make(chan struct{}),
		maxSlots:    slots,
		timeout:     minWaitForData,
	}

	if !e.Config.Passive {
		r.timeout = maxWaitForData
		go r.checkForData()
	}

	return r
}

func (r *enumSource) Stop() {
	r.filter = filter.NewBloomFilter(1)
	r.sweepFilter = filter.NewBloomFilter(1)
	r.queue.Process(func(e interface{}) {})
	r.dups.Process(func(e interface{}) {})
	r.sweeps.Process(func(e interface{}) {})
}

func (r *enumSource) dataSourceName(req *requests.DNSRequest) {
	if req == nil || req.Name == "" {
		return
	}
	if r.enum.Config.IsDomainInScope(req.Name) {
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
	case <-r.enum.ctx.Done():
		return
	case <-r.enum.done:
		return
	case <-r.done:
		return
	default:
	}

	switch v := data.(type) {
	case *requests.DNSRequest:
		if v != nil && v.Valid() {
			r.newName(ctx, v, tp)
		}
	case *requests.AddrRequest:
		if v != nil && v.Valid() {
			r.newAddr(ctx, v, tp)
		}
	}
}

func (r *enumSource) newName(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
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
		r.sweeps.Append(&aRequest{
			Ctx: ctx,
			Req: req,
			Tp:  tp,
		})
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
	r.Lock()
	defer r.Unlock()

	// Check if it's time to reset our bloom filter due to number of elements seen
	if r.count >= filterMaxSize {
		r.count = 0
		r.filter = filter.NewBloomFilter(filterMaxSize)
	}

	trusted := requests.TrustedTag(tag)
	// Do not submit names from untrusted sources, after already receiving the name
	// from a trusted source
	if !trusted && r.filter.Has(s+strconv.FormatBool(true)) {
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
	if r.filter.Duplicate(s + strconv.FormatBool(trusted)) {
		if name {
			r.dups.Append(&requests.DNSRequest{
				Name:   s,
				Tag:    tag,
				Source: source,
			})
		}
		return false
	}

	r.count++
	return true
}

// Next implements the pipeline InputSource interface.
func (r *enumSource) Next(ctx context.Context) bool {
	select {
	case <-r.done:
		return false
	default:
	}

	if !r.queue.Empty() {
		return true
	}

	t := time.NewTimer(r.timeout)
	defer t.Stop()

	for {
		select {
		case <-r.enum.ctx.Done():
			close(r.done)
			return false
		case <-r.enum.done:
			close(r.done)
			return false
		case <-r.done:
			return false
		case <-t.C:
			close(r.done)
			return false
		case <-r.queue.Signal():
			if !r.queue.Empty() {
				return true
			}
		}
	}
}

// Data implements the pipeline InputSource interface.
func (r *enumSource) Data() pipeline.Data {
	var data pipeline.Data

	if element, ok := r.queue.Next(); ok {
		if d, good := element.(pipeline.Data); good {
			data = d
		}
	}

	return data
}

// Error implements the pipeline InputSource interface.
func (r *enumSource) Error() error {
	return nil
}

func (r *enumSource) checkForData() {
	required := r.maxSlots
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	worth := 50 * len(r.enum.Sys.DataSources())
	if r.enum.Config.Alterations {
		worth += 1000
	}
	if r.enum.Config.BruteForcing && r.enum.Config.MinForRecursive == 0 {
		worth += len(r.enum.Config.Wordlist)
	}

	for {
		select {
		case <-r.enum.ctx.Done():
			return
		case <-r.enum.done:
			return
		case <-r.done:
			return
		case <-t.C:
			if needed := required - r.queue.Len(); needed > 0 {
				num := 1

				if n := needed / worth; n > num {
					num = n
				}

				r.enum.subTask.OutputRequests(num)
				r.requestSweeps(needed)
			}
		}
	}
}

// This goroutine ensures that duplicate names from other sources are shown in the Graph.
func (r *enumSource) processDupNames() {
	uuid := r.enum.Config.UUID.String()

	type altsource struct {
		Name      string
		Source    string
		Tag       string
		Timestamp time.Time
	}

	var pending []*altsource
	each := func(element interface{}) {
		req := element.(*requests.DNSRequest)

		pending = append(pending, &altsource{
			Name:      req.Name,
			Source:    req.Source,
			Tag:       req.Tag,
			Timestamp: time.Now(),
		})
	}

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-r.enum.done:
			break loop
		case <-r.dups.Signal():
			r.dups.Process(each)
		case now := <-t.C:
			select {
			case <-r.enum.ctx.Done():
				break loop
			default:
			}

			var count int
			for _, a := range pending {
				if now.Before(a.Timestamp.Add(10 * time.Minute)) {
					break
				}
				if _, err := r.enum.Graph.ReadNode(a.Name, "fqdn"); err == nil {
					_, _ = r.enum.Graph.UpsertFQDN(a.Name, a.Source, uuid)
				}
				count++
			}
			pending = pending[count:]
		}
	}

	select {
	case <-r.enum.ctx.Done():
		return
	default:
	}

	r.dups.Process(each)
	for _, a := range pending {
		if _, err := r.enum.Graph.ReadNode(a.Name, "fqdn"); err == nil {
			_, _ = r.enum.Graph.UpsertFQDN(a.Name, a.Source, uuid)
		}
	}
}

type aRequest struct {
	Ctx context.Context
	Req *requests.AddrRequest
	Tp  pipeline.TaskParams
}

func (r *enumSource) requestSweeps(num int) int {
	var count int

	for count < num {
		e, ok := r.sweeps.Next()
		if !ok {
			break
		}

		if q, good := e.(*aRequest); good {
			// Generate the additional addresses to sweep across
			count += r.sweepAddrs(q.Ctx, q.Req, q.Tp)
		}
	}

	return count
}

func (r *enumSource) sweepAddrs(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) int {
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

		if a := ip.String(); !r.sweepFilter.Duplicate(a) {
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
