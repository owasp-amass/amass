// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"time"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
)

const (
	minWaitForData = 5 * time.Second
	maxWaitForData = 30 * time.Second
)

// enumSource handles the filtering and release of new Data in the enumeration.
type enumSource struct {
	enum     *Enumeration
	queue    queue.Queue
	done     chan struct{}
	maxSlots int
	timeout  time.Duration
}

// newEnumSource returns an initialized input source for the enumeration pipeline.
func newEnumSource(e *Enumeration, slots int) *enumSource {
	r := &enumSource{
		enum:     e,
		queue:    queue.NewQueue(),
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
	if r.enum.Config.IsDomainInScope(req.Name) {
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

	if req != nil {
		r.queue.Append(req)
	}
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
			if r.queue.Len() < required {
				r.enum.subTask.OutputRequests(required - r.queue.Len())
			}
		}
	}
}
