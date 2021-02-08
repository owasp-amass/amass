// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package intel

import (
	"context"
	"time"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
)

const minWaitForData = 10 * time.Second

// intelSource handles the filtering and release of new Data in the enumeration.
type intelSource struct {
	collection *Collection
	filter     *stringfilter.StringFilter
	queue      queue.Queue
	done       chan struct{}
	timeout    time.Duration
}

// newIntelSource returns an initialized input source for the intelligence pipeline.
func newIntelSource(c *Collection) *intelSource {
	return &intelSource{
		collection: c,
		filter:     stringfilter.NewStringFilter(),
		queue:      queue.NewQueue(),
		done:       make(chan struct{}),
		timeout:    minWaitForData,
	}
}

// InputAddress allows the input source to accept new addresses from data sources.
func (r *intelSource) InputAddress(req *requests.AddrRequest) {
	select {
	case <-r.done:
		return
	default:
	}

	if req != nil && !r.filter.Duplicate(req.Address) {
		r.queue.Append(req)
	}
}

// Next implements the pipeline InputSource interface.
func (r *intelSource) Next(ctx context.Context) bool {
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
func (r *intelSource) Data() pipeline.Data {
	if element, ok := r.queue.Next(); ok {
		return element.(pipeline.Data)
	}
	return nil
}

// Error implements the pipeline InputSource interface.
func (r *intelSource) Error() error {
	return nil
}
