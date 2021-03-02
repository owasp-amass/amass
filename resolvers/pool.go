// Copyright 2017-2021 Jeff Foley. All rights reserved.
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

type resolverPool struct {
	sync.Mutex
	done chan struct{}
	// Logger for error messages
	log            *log.Logger
	baseline       Resolver
	partitions     [][]Resolver
	sfcount        int
	curPart        int
	last           time.Time
	curIdx         int
	avgs           *slidingWindowTimeouts
	waits          map[string]time.Time
	delay          time.Duration
	hasBeenStopped bool
}

// NewResolverPool initializes a ResolverPool that uses the provided Resolvers.
func NewResolverPool(resolvers []Resolver, delay time.Duration, baseline Resolver, partnum int, logger *log.Logger) Resolver {
	if l := len(resolvers); l == 0 || l > len(resolvers) {
		return nil
	}
	if partnum <= 0 {
		partnum = 1
	}

	rp := &resolverPool{
		baseline:   baseline,
		partitions: make([][]Resolver, partnum),
		last:       time.Now(),
		avgs:       newSlidingWindowTimeouts(),
		waits:      make(map[string]time.Time),
		delay:      delay,
		done:       make(chan struct{}, 2),
		log:        logger,
	}

	num := len(resolvers) / partnum
	for i := 0; i < partnum; i++ {
		start := i * num
		end := (start + num) - 1

		if i == partnum-1 {
			rp.partitions[i] = resolvers[start:]
		} else {
			rp.partitions[i] = resolvers[start:end]
		}
	}

	// Assign a null logger when one is not provided
	if rp.log == nil {
		rp.log = log.New(ioutil.Discard, "", 0)
	}

	return rp
}

// Stop implements the Resolver interface.
func (rp *resolverPool) Stop() {
	if rp.hasBeenStopped {
		return
	}
	rp.hasBeenStopped = true
	close(rp.done)

	for _, partition := range rp.partitions {
		for _, r := range partition {
			r.Stop()
		}
	}

	if rp.baseline != nil {
		rp.baseline.Stop()
	}

	rp.partitions = [][]Resolver{}
	return
}

// Stopped implements the Resolver interface.
func (rp *resolverPool) Stopped() bool {
	return rp.hasBeenStopped
}

// String implements the Stringer interface.
func (rp *resolverPool) String() string {
	return "ResolverPool"
}

func (rp *resolverPool) nextResolver(ctx context.Context) Resolver {
	var count int
	var r Resolver

	for {
		if checkContext(ctx) != nil {
			break
		}

		rp.Lock()
		if rp.sfcount > 5 {
			rp.nextPartition()
		}

		part := rp.curPart
		idx := rp.curIdx
		rp.curIdx++
		rp.curIdx = rp.curIdx % len(rp.partitions[part])
		r = rp.partitions[part][idx]
		t, found := rp.waits[r.String()]
		rp.Unlock()

		if (!found || t.IsZero() || time.Now().After(t)) && !r.Stopped() {
			break
		}

		count++
		count = count % len(rp.partitions[part])
		if count == 0 || count > 5 {
			rp.Lock()
			rp.nextPartition()
			rp.Unlock()
		}
	}

	return r
}

func (rp *resolverPool) nextPartition() {
	if time.Now().Before(rp.last.Add(30 * time.Second)) {
		return
	}

	rp.curPart++
	rp.curPart = rp.curPart % len(rp.partitions)
	rp.last = time.Now()
	rp.curIdx = 0
}

func (rp *resolverPool) incServfailCount() {
	rp.Lock()
	defer rp.Unlock()

	if time.Now().Before(rp.last.Add(30 * time.Second)) {
		return
	}
	rp.sfcount++
}

func (rp *resolverPool) updateWait(key string, d time.Duration) {
	rp.Lock()
	defer rp.Unlock()

	rp.waits[key] = time.Now().Add(d)
}

func (rp *resolverPool) numUsableResolvers() int {
	rp.Lock()
	defer rp.Unlock()

	var num int
	now := time.Now()
	for _, partition := range rp.partitions {
		for _, r := range partition {
			t, found := rp.waits[r.String()]

			if (!found || t.IsZero() || now.After(t)) && !r.Stopped() {
				num++
			}
		}
	}
	return num
}

// Query implements the Stringer interface.
func (rp *resolverPool) Query(ctx context.Context, msg *dns.Msg, priority int, retry Retry) (*dns.Msg, error) {
	if rp.baseline != nil && rp.numUsableResolvers() == 0 {
		return rp.baseline.Query(ctx, msg, priority, retry)
	}

	var err error
	var r Resolver
	var resp *dns.Msg
	for times := 1; !attemptsExceeded(times, priority); times++ {
		err = checkContext(ctx)
		if err != nil {
			break
		}

		r = rp.nextResolver(ctx)
		if r == nil {
			break
		}

		resp, err = r.Query(ctx, msg, priority, nil)

		var timeout bool
		// Check if the response is considered a resolver failure to be tracked
		if err != nil {
			if e, ok := err.(*ResolveError); ok && e.Rcode == TimeoutRcode {
				timeout = true
			}
		}

		k := r.String()
		// Pause use of the resolver if queries have failed too often
		if rp.avgs.updateTimeouts(k, timeout) && timeout {
			rp.updateWait(k, rp.delay)
		}

		if err == nil {
			break
		}
		// Timeouts and resolver errors can cause retries without executing the callback
		if e, ok := err.(*ResolveError); ok && (e.Rcode == TimeoutRcode || e.Rcode == ResolverErrRcode) {
			continue
		} else if ok && e.Rcode == dns.RcodeServerFailure {
			rp.incServfailCount()
			continue
		}

		if retry == nil || !retry(times, priority, resp) {
			break
		}
	}

	if rp.baseline != nil && err == nil && len(resp.Answer) > 0 {
		// Validate findings from an untrusted resolver
		resp, err = rp.baseline.Query(ctx, msg, priority, retry)
		// False positives result in stopping the untrusted resolver
		if err == nil && resp != nil && len(resp.Answer) == 0 {
			r.Stop()
		}
	}

	return resp, err
}

// WildcardType implements the Stringer interface.
func (rp *resolverPool) WildcardType(ctx context.Context, msg *dns.Msg, domain string) int {
	if rp.baseline != nil {
		return rp.baseline.WildcardType(ctx, msg, domain)
	}
	return rp.partitions[0][0].WildcardType(ctx, msg, domain)
}
