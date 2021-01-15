// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"io/ioutil"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type roundRobin struct {
	sync.Mutex
	done chan struct{}
	// Logger for error messages
	log            *log.Logger
	baseline       Resolver
	resolvers      []Resolver
	curIdx         int
	avgs           *slidingWindowTimeouts
	waits          map[string]time.Time
	hasBeenStopped bool
}

// NewRoundRobin initializes a round robin resolver pool that uses the provided Resolvers.
func NewRoundRobin(resolvers []Resolver, logger *log.Logger) Resolver {
	rr := &roundRobin{
		baseline:  resolvers[0],
		resolvers: resolvers,
		done:      make(chan struct{}, 2),
		log:       logger,
		avgs:      newSlidingWindowTimeouts(),
		waits:     make(map[string]time.Time),
	}

	// Assign a null logger when one is not provided
	if rr.log == nil {
		rr.log = log.New(ioutil.Discard, "", 0)
	}

	return rr
}

// Stop calls the Stop method for each Resolver object in the pool.
func (rr *roundRobin) Stop() error {
	if rr.hasBeenStopped {
		return nil
	}
	rr.hasBeenStopped = true
	close(rr.done)

	for _, r := range rr.resolvers {
		r.Stop()
	}

	rr.resolvers = []Resolver{}
	return nil
}

// Stopped implements the Resolver interface.
func (rr *roundRobin) Stopped() bool {
	return rr.hasBeenStopped
}

// String implements the Stringer interface.
func (rr *roundRobin) String() string {
	return "RoundRobin"
}

func (rr *roundRobin) nextResolver(ctx context.Context) Resolver {
	var count int
	var r Resolver

	for {
		if checkContext(ctx) != nil {
			break
		}

		rr.Lock()
		idx := rr.curIdx
		rr.curIdx++
		rr.curIdx = rr.curIdx % len(rr.resolvers)
		r = rr.resolvers[idx]
		t, found := rr.waits[r.String()]
		rr.Unlock()

		if (!found || t.IsZero() || time.Now().After(t)) && !r.Stopped() {
			break
		}

		count++
		count = count % len(rr.resolvers)
		if count == 0 {
			time.Sleep(5 * time.Second)
		}
	}

	return r
}

func (rr *roundRobin) updateWait(key string, d time.Duration) {
	rr.Lock()
	defer rr.Unlock()

	rr.waits[key] = time.Now().Add(d)
}

// Query implements the Resolver interface.
func (rr *roundRobin) Query(ctx context.Context, msg *dns.Msg, priority int, retry Retry) (*dns.Msg, error) {
	again := true
	var times int
	var err error
	var r Resolver
	var resp *dns.Msg

	for again {
		err = checkContext(ctx)
		if err != nil {
			break
		}

		r = rr.nextResolver(ctx)
		if r == nil {
			break
		}

		resp, err = r.Query(ctx, msg, priority, nil)

		var timeout bool
		if err != nil {
			if e, ok := err.(*ResolveError); ok && (e.Rcode == TimeoutRcode ||
				e.Rcode == dns.RcodeServerFailure || e.Rcode == dns.RcodeRefused) {
				timeout = true
			}
		}

		k := r.String()
		// Pause using the resolver if queries have timed out too much
		if rr.avgs.updateTimeouts(k, timeout) && timeout {
			rr.updateWait(k, 30*time.Second)
		}

		if err == nil {
			break
		}

		if err != nil {
			if e, ok := err.(*ResolveError); ok && (e.Rcode == TimeoutRcode || e.Rcode == ResolverErrRcode) {
				continue
			}
		}

		if retry != nil {
			times++
			again = retry(times, priority, resp)
		}
	}

	return resp, err
}

// WildcardType implements the Resolver interface.
func (rr *roundRobin) WildcardType(ctx context.Context, msg *dns.Msg, domain string) int {
	return rr.baseline.WildcardType(ctx, msg, domain)
}
