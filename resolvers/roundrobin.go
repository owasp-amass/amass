// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	"github.com/miekg/dns"
)

type avgInfo struct {
	Timeouts float64
	Num      float64
}

type roundRobin struct {
	sync.Mutex
	done chan struct{}
	// Logger for error messages
	log            *log.Logger
	baseline       Resolver
	resolvers      []Resolver
	curIdx         int
	timeoutLock    sync.Mutex
	timeoutAvgs    map[string]*avgInfo
	hasBeenStopped bool
}

// NewRoundRobin initializes a round robin resolver pool that uses the provided Resolvers.
func NewRoundRobin(resolvers []Resolver, logger *log.Logger) Resolver {
	rr := &roundRobin{
		baseline:    resolvers[0],
		resolvers:   resolvers,
		timeoutAvgs: make(map[string]*avgInfo, len(resolvers)),
		done:        make(chan struct{}, 2),
		log:         logger,
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

func (rr *roundRobin) updateTimeouts(key string, timeout bool) bool {
	rr.timeoutLock.Lock()
	defer rr.timeoutLock.Unlock()

	if _, found := rr.timeoutAvgs[key]; !found {
		rr.timeoutAvgs[key] = new(avgInfo)
	}

	data := rr.timeoutAvgs[key]
	if timeout {
		data.Timeouts++
	}
	data.Num++

	var stop bool
	if data.Num > 10 && data.Timeouts/data.Num > 0.95 {
		stop = true
	}

	return stop
}

func (rr *roundRobin) nextResolver() Resolver {
	if rr.numUsableResolvers() == 0 {
		return nil
	}

	var r Resolver
	for {
		rr.Lock()
		idx := rr.curIdx
		rr.curIdx++
		rr.curIdx = rr.curIdx % len(rr.resolvers)
		rr.Unlock()

		r = rr.resolvers[idx]
		if !r.Stopped() {
			break
		}
	}

	return r
}

// Query implements the Resolver interface.
func (rr *roundRobin) Query(ctx context.Context, msg *dns.Msg, priority int, retry Retry) (*dns.Msg, error) {
	if rr.numUsableResolvers() == 0 {
		return nil, &ResolveError{
			Err:   fmt.Sprintf("All resolvers have been stopped"),
			Rcode: ResolverErrRcode,
		}
	}

	again := true
	var times int
	var err error
	var resp *dns.Msg
	for again {
		err = checkContext(ctx)
		if err != nil {
			break
		}

		r := rr.nextResolver()
		if r == nil {
			return nil, &ResolveError{
				Err:   fmt.Sprintf("All resolvers have been stopped"),
				Rcode: ResolverErrRcode,
			}
		}

		times++
		resp, err = r.Query(ctx, msg, priority, nil)
		if resp != nil && (resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeServerFailure) {
			r.Stop()
		}

		var timeout bool
		if err != nil {
			if e, ok := err.(*ResolveError); ok && e.Rcode == TimeoutRcode {
				timeout = true
			}
		}
		// Stop the resolver if queries have timed out too many times
		if rr.updateTimeouts(r.String(), timeout) {
			r.Stop()
		}

		if err == nil || retry == nil {
			break
		}
		again = retry(times, priority, resp)
	}

	return resp, err
}

// WildcardType implements the Resolver interface.
func (rr *roundRobin) WildcardType(ctx context.Context, msg *dns.Msg, domain string) int {
	return rr.baseline.WildcardType(ctx, msg, domain)
}

func (rr *roundRobin) numUsableResolvers() int {
	var num int

	for _, r := range rr.resolvers {
		if !r.Stopped() {
			num++
		}
	}

	return num
}
