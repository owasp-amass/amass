// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"sync"
	"time"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/service"
	"github.com/owasp-amass/amass/v4/requests"
	bf "github.com/tylertreat/BoomFilters"
)

const waitForDuration = 10 * time.Second

// enumSource handles the filtering and release of new Data in the enumeration.
type enumSource struct {
	pipeline *pipeline.Pipeline
	enum     *Enumeration
	queue    queue.Queue
	filter   *bf.StableBloomFilter
	done     chan struct{}
	doneOnce sync.Once
	release  chan struct{}
	max      int
}

// newEnumSource returns an initialized input source for the enumeration pipeline.
func newEnumSource(p *pipeline.Pipeline, e *Enumeration) *enumSource {
	size := e.Sys.TrustedResolvers().Len() * e.Config.TrustedQPS

	r := &enumSource{
		pipeline: p,
		enum:     e,
		queue:    queue.NewQueue(),
		filter:   bf.NewDefaultStableBloomFilter(1000000, 0.01),
		done:     make(chan struct{}),
		release:  make(chan struct{}, size),
		max:      size,
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
	for i := 0; i < size; i++ {
		r.release <- struct{}{}
	}
	return r
}

func (r *enumSource) Stop() {
	r.markDone()
	r.queue.Process(func(e interface{}) {})
	r.filter.Reset()
}

func (r *enumSource) markDone() {
	r.doneOnce.Do(func() {
		close(r.done)
	})
}

func (r *enumSource) newName(req *requests.DNSRequest) {
	select {
	case <-r.done:
		return
	default:
	}

	if req.Name == "" || !req.Valid() {
		r.releaseOutput(1)
		return
	}
	// Clean up the newly discovered name and domain
	requests.SanitizeDNSRequest(req)

	if r.enum.Config.Blacklisted(req.Name) {
		r.releaseOutput(1)
		return
	}
	if !r.accept(req.Name) {
		r.releaseOutput(1)
		return
	}
	r.queue.Append(req)
}

func (r *enumSource) newAddr(req *requests.AddrRequest) {
	select {
	case <-r.done:
		return
	default:
	}

	if req.Valid() && req.InScope && r.accept(req.Address) {
		r.queue.Append(req)
	}
}

func (r *enumSource) accept(s string) bool {
	return !r.filter.TestAndAdd([]byte(s))
}

// Next implements the pipeline InputSource interface.
func (r *enumSource) Next(ctx context.Context) bool {
	// Low if below 75%
	if p := (float32(r.queue.Len()) / float32(r.max)) * 100; p < 75 {
		r.fillQueue()
	}

	t := time.NewTimer(waitForDuration)
	defer t.Stop()

	for {
		select {
		case <-r.done:
			return false
		case <-ctx.Done():
			r.markDone()
			return false
		case <-t.C:
			count := r.pipeline.DataItemCount()
			if !r.enum.requestsPending() && count <= 0 {
				if r.enum.store.queue.Len() == 0 {
					r.markDone()
					return false
				}
			}
			r.fillQueue()
			t.Reset(waitForDuration)
		case <-r.queue.Signal():
			return true
		}
	}
}

// Data implements the pipeline InputSource interface.
func (r *enumSource) Data() pipeline.Data {
	var data pipeline.Data

	if element, ok := r.queue.Next(); ok {
		data = element.(pipeline.Data)
	}
	return data
}

// Error implements the pipeline InputSource interface.
func (r *enumSource) Error() error {
	return nil
}

func (r *enumSource) fillQueue() {
	if unfilled := r.max - r.queue.Len(); unfilled > 0 {
		if fill := unfilled - len(r.release); fill > 0 {
			r.releaseOutput(fill)
		}
	}
}

func (r *enumSource) releaseOutput(num int) {
loop:
	for i := 0; i < num; i++ {
		select {
		case r.release <- struct{}{}:
		default:
			break loop
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
				r.newAddr(req)
			}
		}
	}
}
