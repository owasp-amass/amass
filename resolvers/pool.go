// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/limits"
	amassnet "github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/miekg/dns"
	"golang.org/x/sync/semaphore"
)

// ResolverPool manages many DNS resolvers for high-performance use, such as brute forcing attacks.
type ResolverPool struct {
	Resolvers []Resolver
	Done      chan struct{}
	// Logger for error messages
	Log             *log.Logger
	domainCacheChan chan *domainReq
	hasBeenStopped  bool
	wildcardQueue   *queue.Queue
	semMaxWildcard  *semaphore.Weighted
}

// SetupResolverPool initializes a ResolverPool with the type of resolvers indicated by the parameters.
func SetupResolverPool(addrs []string, maxQueries int, ratemon bool, log *log.Logger) *ResolverPool {
	if len(addrs) <= 0 {
		return nil
	}

	// Do not allow the number of resolvers to exceed the ulimit
	temp := addrs
	addrs = []string{}
	max := int(float64(limits.GetFileLimit())*0.7) / 2
	for i, r := range temp {
		if i > max {
			break
		}
		addrs = append(addrs, r)
	}

	finished := make(chan Resolver, 100)
	for _, addr := range addrs {
		go func(ip string, ch chan Resolver) {
			if n := NewBaseResolver(ip); n != nil {
				ch <- n
				return
			}
			ch <- nil
		}(addr, finished)
	}

	l := len(addrs)
	var resolvers []Resolver
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
loop:
	for i := 0; i < l; i++ {
		select {
		case <-t.C:
			break loop
		case r := <-finished:
			if r == nil {
				continue loop
			}
			if ratemon {
				if r = NewRateMonitoredResolver(r); r == nil {
					continue loop
				}
			}
			resolvers = append(resolvers, r)
		}
	}

	if len(resolvers) == 0 {
		return nil
	}

	return NewResolverPool(resolvers, maxQueries, log)
}

// NewResolverPool initializes a ResolverPool that uses the provided Resolvers.
func NewResolverPool(res []Resolver, maxQueries int, logger *log.Logger) *ResolverPool {
	rp := &ResolverPool{
		Resolvers:       res,
		Done:            make(chan struct{}, 2),
		Log:             logger,
		domainCacheChan: make(chan *domainReq, 10),
		wildcardQueue:   queue.NewQueue(),
		semMaxWildcard:  semaphore.NewWeighted(int64(100000 / len(res))),
	}

	// Assign a null logger when one is not provided
	if rp.Log == nil {
		rp.Log = log.New(ioutil.Discard, "", 0)
	}

	go rp.processWildcardRequests()
	go rp.manageDomainCache(rp.domainCacheChan)
	return rp
}

// Stop calls the Stop method for each Resolver object in the pool.
func (rp *ResolverPool) Stop() error {
	if rp.hasBeenStopped {
		return nil
	}
	rp.hasBeenStopped = true
	close(rp.Done)

	for _, r := range rp.Resolvers {
		r.Stop()
	}

	rp.Resolvers = []Resolver{}
	return nil
}

// IsStopped implements the Resolver interface.
func (rp *ResolverPool) IsStopped() bool {
	return rp.hasBeenStopped
}

// Address implements the Resolver interface.
func (rp *ResolverPool) Address() string {
	return "N/A"
}

// Port implements the Resolver interface.
func (rp *ResolverPool) Port() int {
	return 0
}

// String implements the Stringer interface.
func (rp *ResolverPool) String() string {
	return "ResolverPool"
}

// Available returns true if the Resolver can handle another DNS request.
func (rp *ResolverPool) Available() (bool, error) {
	return true, nil
}

// Stats returns performance counters.
func (rp *ResolverPool) Stats() map[int]int64 {
	stats := make(map[int]int64)

	for _, r := range rp.Resolvers {
		for k, v := range r.Stats() {
			if cur, found := stats[k]; found {
				stats[k] = cur + v
			} else {
				stats[k] = v
			}
		}
	}

	return stats
}

// WipeStats clears the performance counters.
func (rp *ResolverPool) WipeStats() {
	return
}

// ReportError implements the Resolver interface.
func (rp *ResolverPool) ReportError() {
	return
}

// SubdomainToDomain returns the first subdomain name of the provided
// parameter that responds to a DNS query for the NS record type.
func (rp *ResolverPool) SubdomainToDomain(name string) string {
	ch := make(chan string, 2)

	rp.domainCacheChan <- &domainReq{
		Name: name,
		Ch:   ch,
	}

	return <-ch
}

type domainReq struct {
	Name string
	Ch   chan string
}

func (rp *ResolverPool) manageDomainCache(ch chan *domainReq) {
	cache := make(map[string]struct{})
loop:
	for {
		select {
		case <-rp.Done:
			return
		case req := <-ch:
			var domain string
			// Obtain all parts of the subdomain name
			labels := strings.Split(strings.TrimSpace(req.Name), ".")
			// Check the cache for all parts of the name
			for i := len(labels); i >= 0; i-- {
				sub := strings.Join(labels[i:], ".")

				if _, ok := cache[sub]; ok {
					domain = sub
					break
				}
			}
			if domain != "" {
				req.Ch <- domain
				continue loop
			}
			// Check the DNS for all parts of the name
			for i := 0; i < len(labels)-1; i++ {
				sub := strings.Join(labels[i:], ".")

				if ns, _, err := rp.Resolve(context.TODO(), sub, "NS", PriorityHigh); err == nil {
					pieces := strings.Split(ns[0].Data, ",")
					cache[pieces[0]] = struct{}{}
					domain = pieces[0]
					break
				}
			}

			req.Ch <- domain
		}
	}
}

// NextResolver returns a randomly selected Resolver from the pool that has availability.
func (rp *ResolverPool) NextResolver() Resolver {
	var attempts int
	max := len(rp.Resolvers)

	if max == 0 || rp.numUsableResolvers() == 0 {
		return nil
	}

	for {
		r := rp.Resolvers[rand.Int()%max]

		if avail, _ := r.Available(); avail {
			return r
		}

		attempts++
		if attempts > max {
			// Check every resolver sequentially
			for _, r := range rp.Resolvers {
				if avail, _ := r.Available(); avail {
					return r
				}
			}
			break
		}
	}

	return nil
}

// Reverse is performs reverse DNS queries using available Resolvers in the pool.
func (rp *ResolverPool) Reverse(ctx context.Context, addr string, priority int) (string, string, error) {
	var name, ptr string

	if ip := net.ParseIP(addr); amassnet.IsIPv4(ip) {
		ptr = amassdns.ReverseIP(addr) + ".in-addr.arpa"
	} else if amassnet.IsIPv6(ip) {
		ptr = amassdns.IPv6NibbleFormat(ip.String()) + ".ip6.arpa"
	} else {
		return ptr, "", &ResolveError{
			Err:   fmt.Sprintf("Invalid IP address parameter: %s", addr),
			Rcode: ResolverErrRcode,
		}
	}

	answers, _, err := rp.Resolve(ctx, ptr, "PTR", priority)
	if err != nil {
		return ptr, name, err
	}

	for _, a := range answers {
		if a.Type == 12 {
			name = RemoveLastDot(a.Data)
			break
		}
	}

	if name == "" {
		err = &ResolveError{
			Err:   fmt.Sprintf("PTR record not found for IP address: %s", addr),
			Rcode: ResolverErrRcode,
		}
	} else if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		err = &ResolveError{
			Err:   fmt.Sprintf("Invalid target in PTR record answer: %s", name),
			Rcode: ResolverErrRcode,
		}
	}

	return ptr, name, err
}

// Resolve performs a DNS request using available Resolvers in the pool.
func (rp *ResolverPool) Resolve(ctx context.Context, name, qtype string, priority int) ([]requests.DNSAnswer, bool, error) {
	var attempts int
	switch priority {
	case PriorityCritical:
		attempts = 1000
	case PriorityHigh:
		attempts = 250
	case PriorityLow:
		attempts = 50
	}

	var err error
	var again bool
	var ans []requests.DNSAnswer
	// This loop ensures the correct number of attempts of the DNS query
	for count := 0; count < attempts; {
		r := rp.NextResolver()
		if r == nil {
			// Give the system a chance to breathe before trying again
			time.Sleep(time.Duration(randomInt(100, 200)) * time.Millisecond)
			continue
		}

		count++
		success := true
		ans, again, err = r.Resolve(ctx, name, qtype, priority)
		if again {
			success = false
		} else if err != nil {
			if rc := (err.(*ResolveError)).Rcode; rc == TimeoutRcode ||
				rc == dns.RcodeServerFailure || rc == dns.RcodeRefused || rc == dns.RcodeNotImplemented {
				success = false
			}
		}

		if success {
			return ans, again, err
		}
	}

	return []requests.DNSAnswer{}, false, err
}

// NsecTraversal performs NSEC-walking using available Resolvers in the pool.
func (rp *ResolverPool) NsecTraversal(ctx context.Context, domain string, priority int) ([]string, bool, error) {
	var attempts int
	switch priority {
	case PriorityCritical:
		attempts = 1000
	case PriorityHigh:
		attempts = 250
	case PriorityLow:
		attempts = 50
	}

	var err error
	var again bool
	var ans []string
	// This loop ensures the correct number of attempts of the DNS query
	for count := 0; count < attempts; {
		r := rp.NextResolver()
		if r == nil {
			// Give the system a chance to breathe before trying again
			time.Sleep(time.Duration(randomInt(100, 200)) * time.Millisecond)
			continue
		}

		count++
		ans, again, err = r.NsecTraversal(ctx, domain, priority)
		if !again {
			return ans, again, err
		}
	}

	return []string{}, false, err
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (rp *ResolverPool) MatchesWildcard(ctx context.Context, req *requests.DNSRequest) bool {
	ch := make(chan int, 2)

	rp.wildcardQueue.Append(&wildcardQueueMsg{
		Ctx: ctx,
		Req: req,
		Ch:  ch,
	})

	var matched bool
	if wtype := <-ch; wtype != WildcardTypeNone {
		matched = true
	}

	return matched
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (rp *ResolverPool) GetWildcardType(ctx context.Context, req *requests.DNSRequest) int {
	ch := make(chan int, 2)

	rp.wildcardQueue.Append(&wildcardQueueMsg{
		Ctx: ctx,
		Req: req,
		Ch:  ch,
	})

	return <-ch
}

type wildcardQueueMsg struct {
	Ctx context.Context
	Req *requests.DNSRequest
	Ch  chan int
}

func (rp *ResolverPool) processWildcardRequests() {
	for {
		select {
		case <-rp.Done:
			return
		case <-rp.wildcardQueue.Signal:
			e, found := rp.wildcardQueue.Next()

			for found {
				msg := e.(*wildcardQueueMsg)

				if rp.semMaxWildcard.Acquire(msg.Ctx, 1) == nil {
					go rp.allResolversWildcardRequest(msg)
				}

				e, found = rp.wildcardQueue.Next()
			}
		}
	}
}

func (rp *ResolverPool) allResolversWildcardRequest(msg *wildcardQueueMsg) {
	defer rp.semMaxWildcard.Release(1)

	ch := make(chan int)
	query := func(r Resolver) {
		ch <- <-wrapWildcardRequest(msg.Ctx, r, msg.Req)
	}

	var num int
	// Allowing the wildcard requests to be performed concurrently on the first attempt
	for _, resolver := range rp.Resolvers {
		if stopped := resolver.IsStopped(); stopped {
			continue
		}

		go query(resolver)
		num++
	}

	var static, dynamic bool
	for i := 0; i < num; i++ {
		wtype := <-ch

		switch wtype {
		case WildcardTypeStatic:
			static = true
		case WildcardTypeDynamic:
			dynamic = true
		}
	}

	ret := WildcardTypeNone
	if dynamic {
		ret = WildcardTypeDynamic
	} else if static {
		ret = WildcardTypeStatic
	}

	msg.Ch <- ret
}

func wrapWildcardRequest(ctx context.Context, resolver Resolver, req *requests.DNSRequest) chan int {
	ch := make(chan int, 2)

	if stopped := resolver.IsStopped(); stopped {
		ch <- WildcardTypeNone
	} else {
		ch <- resolver.GetWildcardType(ctx, req)
	}

	return ch
}

func (rp *ResolverPool) numUsableResolvers() int {
	var num int

	for _, r := range rp.Resolvers {
		if stopped := r.IsStopped(); !stopped {
			num++
		}
	}
	return num
}

func randomInt(min, max int) int {
	return min + rand.Intn((max-min)+1)
}
