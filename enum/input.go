// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/filter"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
)

const (
	minWaitForData = 15 * time.Second
	maxWaitForData = 30 * time.Second
)

// enumSource handles the filtering and release of new Data in the enumeration.
type enumSource struct {
	sync.Mutex
	enum     *Enumeration
	queue    queue.Queue
	filter   filter.Filter
	count    int64
	done     chan struct{}
	maxSlots int
	timeout  time.Duration
}

// newEnumSource returns an initialized input source for the enumeration pipeline.
func newEnumSource(e *Enumeration, slots int) *enumSource {
	r := &enumSource{
		enum:     e,
		queue:    queue.NewQueue(),
		filter:   filter.NewBloomFilter(filterMaxSize),
		done:     make(chan struct{}),
		maxSlots: slots,
		timeout:  minWaitForData,
	}

	if !e.Config.Passive {
		r.timeout = maxWaitForData
		go r.checkForData()
	}

	return r
}

// InputName allows the input source to accept new names from data sources.
func (r *enumSource) InputName(req *requests.DNSRequest) {
	select {
	case <-r.done:
		return
	default:
	}

	if req == nil || req.Name == "" {
		return
	}
	if r.accept(req.Name, req.Tag) && r.enum.Config.IsDomainInScope(req.Name) {
		r.queue.Append(req)
	}
}

// InputAddress allows the input source to accept new addresses from data sources.
func (r *enumSource) InputAddress(req *requests.AddrRequest) {
	select {
	case <-r.done:
		return
	default:
	}

	if req != nil && req.Address != "" && r.accept(req.Address, req.Tag) {
		r.queue.Append(req)
	}
}

func (r *enumSource) accept(s string, tag string) bool {
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
		return false
	}
	// At most, a FQDN will be accepted from an untrusted source first, and then
	// reconsidered from a trusted data source
	if r.filter.Duplicate(s + strconv.FormatBool(trusted)) {
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
	if element, ok := r.queue.Next(); ok {
		return element.(pipeline.Data)
	}
	return nil
}

// Error implements the pipeline InputSource interface.
func (r *enumSource) Error() error {
	return nil
}

func (r *enumSource) checkForData() {
	required := r.maxSlots * 10
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-r.enum.done:
			return
		case <-r.done:
			return
		case <-t.C:
			if avail := r.queue.Len(); avail < required {
				r.enum.subTask.OutputRequests(required - avail)
			}
		}
	}
}
