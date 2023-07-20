// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"time"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/owasp-amass/amass/v4/requests"
	bf "github.com/tylertreat/BoomFilters"
)

const minWaitForData = 10 * time.Second

// intelSource handles the filtering and release of new Data in the enumeration.
type intelSource struct {
	collection *Collection
	filter     *bf.StableBloomFilter
	queue      queue.Queue
	done       chan struct{}
	timeout    time.Duration
}

// newIntelSource returns an initialized input source for the intelligence pipeline.
func newIntelSource(c *Collection) *intelSource {
	return &intelSource{
		collection: c,
		filter:     bf.NewDefaultStableBloomFilter(1000000, 0.01),
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

	if req != nil && !r.filter.TestAndAdd([]byte(req.Address)) {
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

	return !r.queue.Empty()
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
