// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/filter"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
)

// The filter for new outgoing DNS queries
type fqdnFilter struct {
	sync.Mutex
	filter filter.Filter
	count  int64
	enum   *Enumeration
	queue  queue.Queue
	subre  *regexp.Regexp
}

func newFQDNFilter(e *Enumeration) *fqdnFilter {
	f := &fqdnFilter{
		filter: filter.NewBloomFilter(filterMaxSize),
		enum:   e,
		queue:  queue.NewQueue(),
		subre:  dns.AnySubdomainRegex(),
	}

	go f.processDupNames()
	return f
}

// Stop releases allocated resources by the fqdnFilter.
func (f *fqdnFilter) Stop() {
	f.filter = filter.NewBloomFilter(1)
	f.queue.Process(func(e interface{}) {})
}

func (f *fqdnFilter) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	req, ok := data.(*requests.DNSRequest)
	if !ok {
		return data, nil
	}

	// Clean up the newly discovered name and domain
	requests.SanitizeDNSRequest(req)
	// Check that the name is valid
	if f.subre.FindString(req.Name) != req.Name {
		return nil, nil
	}
	// Do not further evaluate service subdomains
	for _, label := range strings.Split(req.Name, ".") {
		l := strings.ToLower(label)

		if l == "_tcp" || l == "_udp" || l == "_tls" {
			return nil, nil
		}
	}
	// Check that this name has not already been processed
	return f.checkFilter(req), nil
}

func (f *fqdnFilter) checkFilter(req *requests.DNSRequest) *requests.DNSRequest {
	f.Lock()
	defer f.Unlock()

	if !req.Valid() {
		return nil
	}
	// Check if it's time to reset our bloom filter due to number of elements seen
	if f.count >= filterMaxSize {
		f.count = 0
		f.filter = filter.NewBloomFilter(filterMaxSize)
	}

	trusted := requests.TrustedTag(req.Tag)
	// Do not submit names from untrusted sources, after already receiving the name
	// from a trusted source
	if !trusted && f.filter.Has(req.Name+strconv.FormatBool(true)) {
		f.queue.Append(req)
		return nil
	}
	// At most, a FQDN will be accepted from an untrusted source first, and then
	// reconsidered from a trusted data source
	if f.filter.Duplicate(req.Name + strconv.FormatBool(trusted)) {
		f.queue.Append(req)
		return nil
	}

	f.count++
	return req
}

// This goroutine ensures that duplicate names from other sources are shown in the Graph.
func (f *fqdnFilter) processDupNames() {
	uuid := f.enum.Config.UUID.String()

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
		case <-f.enum.done:
			break loop
		case <-f.queue.Signal():
			f.queue.Process(each)
		case now := <-t.C:
			var count int
			for _, a := range pending {
				if now.Before(a.Timestamp.Add(10 * time.Minute)) {
					break
				}
				if _, err := f.enum.Graph.ReadNode(a.Name, "fqdn"); err == nil {
					_, _ = f.enum.Graph.UpsertFQDN(a.Name, a.Source, uuid)
				}
				count++
			}
			pending = pending[count:]
		}
	}

	f.queue.Process(each)
	for _, a := range pending {
		if _, err := f.enum.Graph.ReadNode(a.Name, "fqdn"); err == nil {
			_, _ = f.enum.Graph.UpsertFQDN(a.Name, a.Source, uuid)
		}
	}
}

// subdomainTask handles newly discovered proper subdomain names in the enumeration.
type subdomainTask struct {
	enum      *Enumeration
	queue     queue.Queue
	timesChan chan *timesReq
	done      chan struct{}
}

// newSubdomainTask returns an initialized SubdomainTask.
func newSubdomainTask(e *Enumeration) *subdomainTask {
	r := &subdomainTask{
		enum:      e,
		queue:     queue.NewQueue(),
		timesChan: make(chan *timesReq, 10),
		done:      make(chan struct{}, 2),
	}

	go r.timesManager()
	return r
}

// Stop releases resources allocated by the instance.
func (r *subdomainTask) Stop() {
	close(r.done)
	r.queue.Process(func(e interface{}) {})
}

// Process implements the pipeline Task interface.
func (r *subdomainTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	req, ok := data.(*requests.DNSRequest)
	if !ok {
		return data, nil
	}
	if req == nil || !r.enum.Config.IsDomainInScope(req.Name) {
		return nil, nil
	}

	// Do not further evaluate service subdomains
	for _, label := range strings.Split(req.Name, ".") {
		l := strings.ToLower(label)

		if l == "_tcp" || l == "_udp" || l == "_tls" {
			return nil, nil
		}
	}

	r.queue.Append(&requests.ResolvedRequest{
		Name:    req.Name,
		Domain:  req.Domain,
		Records: append([]requests.DNSAnswer(nil), req.Records...),
		Tag:     req.Tag,
		Source:  req.Source,
	})

	return r.checkForSubdomains(ctx, req, tp)
}

func (r *subdomainTask) checkForSubdomains(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) (pipeline.Data, error) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return req, nil
	}
	// It cannot have fewer labels than the root domain name
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return req, nil
	}

	sub := strings.TrimSpace(strings.Join(labels[1:], "."))
	// CNAMEs are not a proper subdomain
	if r.enum.Graph.IsCNAMENode(sub) {
		return req, nil
	}

	subreq := &requests.SubdomainRequest{
		Name:    sub,
		Domain:  req.Domain,
		Records: append([]requests.DNSAnswer(nil), req.Records...),
		Tag:     req.Tag,
		Source:  req.Source,
		Times:   r.timesForSubdomain(sub),
	}

	r.queue.Append(subreq)
	// First time this proper subdomain has been seen?
	if sub != req.Domain && subreq.Times == 1 {
		pipeline.SendData(ctx, "root", subreq, tp)
	}
	return req, nil
}

// OutputRequests sends discovered subdomain names to the enumeration data sources.
func (r *subdomainTask) OutputRequests(num int) int {
	if num <= 0 {
		return 0
	}

	var count int
loop:
	for {
		select {
		case <-r.enum.ctx.Done():
			break loop
		default:
		}

		element, ok := r.queue.Next()
		if !ok {
			break
		}

		for _, src := range r.enum.srcs {
			switch v := element.(type) {
			case *requests.ResolvedRequest:
				src.Request(r.enum.ctx, v.Clone())
			case *requests.SubdomainRequest:
				src.Request(r.enum.ctx, v.Clone())
			default:
				continue loop
			}
			count++
		}

		if count >= num {
			break
		}
	}

	return count
}

func (r *subdomainTask) timesForSubdomain(sub string) int {
	ch := make(chan int, 2)

	r.timesChan <- &timesReq{
		Sub: sub,
		Ch:  ch,
	}

	return <-ch
}

type timesReq struct {
	Sub string
	Ch  chan int
}

func (r *subdomainTask) timesManager() {
	subdomains := make(map[string]int)

	for {
		select {
		case <-r.done:
			return
		case req := <-r.timesChan:
			times, found := subdomains[req.Sub]
			if found {
				times++
			} else {
				times = 1
			}

			subdomains[req.Sub] = times
			req.Ch <- times
		}
	}
}
