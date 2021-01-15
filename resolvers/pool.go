// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
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
	resolvers      []Resolver
	curIdx         int
	avgs           *slidingWindowTimeouts
	waits          map[string]time.Time
	hasBeenStopped bool
}

// SetupResolverPool initializes a ResolverPool with the type of resolvers indicated by the parameters.
func SetupResolverPool(addrs []string, baseline Resolver, max, perSec int, log *log.Logger) Resolver {
	if len(addrs) <= 0 || baseline == nil {
		return nil
	}

	finished := make(chan Resolver, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	num := len(addrs)
	if num > max {
		num = max
	}

	rate := perSec / num
	for _, addr := range addrs {
		go func(ip string, ch chan Resolver) {
			if n := NewBaseResolver(ip, rate, log); n != nil {
				msg := QueryMsg("www.owasp.org", dns.TypeA)

				if resp, err := n.Query(ctx, msg, PriorityCritical,
					func(times int, priority int, msg *dns.Msg) bool {
						return msg.Rcode == TimeoutRcode && times < 3
					}); err == nil && resp != nil && len(resp.Answer) > 0 {
					ch <- n
					return
				}
			}
			ch <- nil
		}(addr, finished)
	}

	l := len(addrs)
	var count int
	var resolvers []Resolver
	for i := 0; i < l; i++ {
		if r := <-finished; r != nil {
			if count < max {
				resolvers = append(resolvers, r)
				count++
				continue
			}
			r.Stop()
		}
	}

	if len(resolvers) == 0 {
		return nil
	}
	return NewResolverPool(baseline, resolvers, log)
}

// NewResolverPool initializes a ResolverPool that uses the provided Resolvers.
func NewResolverPool(baseline Resolver, resolvers []Resolver, logger *log.Logger) Resolver {
	rp := &resolverPool{
		baseline:  baseline,
		resolvers: resolvers,
		avgs:      newSlidingWindowTimeouts(),
		waits:     make(map[string]time.Time),
		done:      make(chan struct{}, 2),
		log:       logger,
	}

	// Assign a null logger when one is not provided
	if rp.log == nil {
		rp.log = log.New(ioutil.Discard, "", 0)
	}

	return rp
}

// Stop implements the Resolver interface.
func (rp *resolverPool) Stop() error {
	if rp.hasBeenStopped {
		return nil
	}
	rp.hasBeenStopped = true
	close(rp.done)

	for _, r := range rp.resolvers {
		r.Stop()
	}
	rp.baseline.Stop()

	rp.resolvers = []Resolver{}
	return nil
}

// Stopped implements the Resolver interface.
func (rp *resolverPool) Stopped() bool {
	return rp.hasBeenStopped
}

// String implements the Stringer interface.
func (rp *resolverPool) String() string {
	return "ResolverPool"
}

func (rp *resolverPool) nextResolver() Resolver {
	if rp.numUsableResolvers() == 0 {
		return nil
	}

	var count int
	var r Resolver
	for {
		rp.Lock()
		idx := rp.curIdx
		rp.curIdx++
		rp.curIdx = rp.curIdx % len(rp.resolvers)
		r = rp.resolvers[idx]
		t, found := rp.waits[r.String()]
		rp.Unlock()

		if (!found || t.IsZero() || time.Now().After(t)) && !r.Stopped() {
			break
		}

		count++
		count = count % len(rp.resolvers)
		if count == 0 {
			time.Sleep(5 * time.Second)
		}
	}

	return r
}

func (rp *resolverPool) updateWait(key string, d time.Duration) {
	rp.Lock()
	defer rp.Unlock()

	rp.waits[key] = time.Now().Add(d)
}

// Query implements the Stringer interface.
func (rp *resolverPool) Query(ctx context.Context, msg *dns.Msg, priority int, retry Retry) (*dns.Msg, error) {
	if rp.numUsableResolvers() == 0 {
		return rp.baseline.Query(ctx, msg, priority, retry)
	}

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

		r = rp.nextResolver()
		if r == nil {
			return nil, &ResolveError{
				Err:   fmt.Sprintf("All resolvers have been stopped"),
				Rcode: ResolverErrRcode,
			}
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
		if rp.avgs.updateTimeouts(k, timeout) && timeout {
			rp.updateWait(k, 30*time.Second)
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

	if err == nil && len(resp.Answer) > 0 {
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
	return rp.baseline.WildcardType(ctx, msg, domain)
}

func (rp *resolverPool) numUsableResolvers() int {
	var num int

	for _, r := range rp.resolvers {
		if !r.Stopped() {
			num++
		}
	}

	return num
}
