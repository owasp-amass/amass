// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/utils"
	"github.com/miekg/dns"
)

// The priority levels for DNS resolution.
const (
	PriorityLow int = iota
	PriorityHigh
	PriorityCritical
)

var (
	retryCodes = []int{
		dns.RcodeRefused,
		dns.RcodeServerFailure,
		dns.RcodeNotImplemented,
	}

	maxRetries = 3
)

type resolveVote struct {
	Err      error
	Resolver Resolver
	Answers  []requests.DNSAnswer
}

// ResolverPool manages many DNS resolvers for high-performance use, such as brute forcing attacks.
type ResolverPool struct {
	Resolvers    []Resolver
	Done         chan struct{}
	wildcardLock sync.Mutex
	wildcards    map[string]*wildcard
	// Domains discovered by the SubdomainToDomain function
	domainLock  sync.Mutex
	domainCache map[string]struct{}
	activeLock  sync.Mutex
	active      time.Time
}

// SetupResolverPool initializes a ResolverPool with type of resolvers indicated by the parameters.
func SetupResolverPool(addrs []string, scoring, ratemon bool) *ResolverPool {
	if len(addrs) <= 0 {
		return nil
	}

	// Do not allow the number of resolvers to exceed the ulimit
	temp := addrs
	addrs = []string{}
	max := int(float64(utils.GetFileLimit())*0.9) / 2
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
loop:
	for i := 0; i < l; i++ {
		select {
		case r := <-finished:
			if r != nil {
				if scoring {
					if r = NewScoredResolver(r); r == nil {
						continue loop
					}
				}
				if ratemon {
					if r = NewRateMonitoredResolver(r); r == nil {
						continue loop
					}
				}
				resolvers = append(resolvers, r)
			}
		}
	}

	if len(resolvers) == 0 {
		return nil
	}
	return NewResolverPool(SanityCheck(resolvers))
}

// NewResolverPool initializes a ResolverPool that uses the provided Resolvers.
func NewResolverPool(res []Resolver) *ResolverPool {
	return &ResolverPool{
		Resolvers: res,
		Done:        make(chan struct{}, 2),
		wildcards:   make(map[string]*wildcard),
		domainCache: make(map[string]struct{}),
		active:      time.Now(),
	}
}

// Stop calls the Stop method for each Resolver object in the pool.
func (rp *ResolverPool) Stop() {
	for _, r := range rp.Resolvers {
		r.Stop()
	}
	rp.Resolvers = []Resolver{}
}

// Available returns true if the Resolver can handle another DNS request.
func (rp *ResolverPool) Available() bool {
	return true
}

// Stats returns performance counters.
func (rp *ResolverPool) Stats() map[int]int64 {
	return make(map[int]int64)
}

// WipeStats clears the performance counters.
func (rp *ResolverPool) WipeStats() {
	return
}

// ReportError implements the Resolver interface.
func (rp *ResolverPool) ReportError() {
	return
}

// NextResolver returns a randomly selected Resolver from the pool that has availability.
func (rp *ResolverPool) NextResolver() Resolver {
	var attempts int
	max := len(rp.Resolvers)

	if max == 0 {
		return nil
	}

	for {
		r := rp.Resolvers[rand.Int()%max]

		if r.Available() {
			return r
		}

		attempts++
		if attempts <= max {
			continue
		}

		for _, r := range rp.Resolvers {
			if r.Available() {
				return r
			}
		}
		attempts = 0
		time.Sleep(time.Duration(randomInt(1, 500)) * time.Millisecond)
	}
	return nil
}

// SubdomainToDomain returns the first subdomain name of the provided
// parameter that responds to a DNS query for the NS record type.
func (rp *ResolverPool) SubdomainToDomain(name string) string {
	rp.domainLock.Lock()
	defer rp.domainLock.Unlock()

	var domain string
	// Obtain all parts of the subdomain name
	labels := strings.Split(strings.TrimSpace(name), ".")
	// Check the cache for all parts of the name
	for i := len(labels); i >= 0; i-- {
		sub := strings.Join(labels[i:], ".")

		if _, ok := rp.domainCache[sub]; ok {
			domain = sub
			break
		}
	}
	if domain != "" {
		return domain
	}
	// Check the DNS for all parts of the name
	for i := 0; i < len(labels)-1; i++ {
		sub := strings.Join(labels[i:], ".")

		if ns, err := rp.Resolve(sub, "NS", PriorityHigh); err == nil {
			pieces := strings.Split(ns[0].Data, ",")
			rp.domainCache[pieces[0]] = struct{}{}
			domain = pieces[0]
			break
		}
	}
	return domain
}

// Resolve performs a DNS request using available Resolvers in the pool.
func (rp *ResolverPool) Resolve(name, qtype string, priority int) ([]requests.DNSAnswer, error) {
	num := 1
	if rp.numUsableResolvers() >= 3 {
		num = 3
	}

	rp.SetActive()

	var queries int
	ch := make(chan *resolveVote, num)
	for i := 0; i < num; i++ {
		r := rp.NextResolver()
		if r == nil {
			break
		}

		go rp.queryResolver(r, ch, name, qtype, priority)
		queries++
	}

	var votes []*resolveVote
	for i := 0; i < queries; i++ {
		select {
		case v := <-ch:
			votes = append(votes, v)
		}
	}

	rp.SetActive()
	return rp.performElection(votes, name, qtype)
}

// Reverse is performs reverse DNS queries using available Resolvers in the pool.
func (rp *ResolverPool) Reverse(addr string) (string, string, error) {
	var name, ptr string

	if ip := net.ParseIP(addr); utils.IsIPv4(ip) {
		ptr = utils.ReverseIP(addr) + ".in-addr.arpa"
	} else if utils.IsIPv6(ip) {
		ptr = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".ip6.arpa"
	} else {
		return ptr, "", &ResolveError{
			Err:   fmt.Sprintf("Invalid IP address parameter: %s", addr),
			Rcode: 100,
		}
	}

	answers, err := rp.Resolve(ptr, "PTR", PriorityLow)
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
			Rcode: 100,
		}
	} else if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		err = &ResolveError{
			Err:   fmt.Sprintf("Invalid target in PTR record answer: %s", name),
			Rcode: 100,
		}
	}
	return ptr, name, err
}

func (rp *ResolverPool) performElection(votes []*resolveVote, name, qtype string) ([]requests.DNSAnswer, error) {
	if len(votes) == 1 {
		return votes[0].Answers, votes[0].Err
	} else if len(votes) < 3 || (votes[0].Err != nil && votes[1].Err != nil && votes[2].Err != nil) {
		return []requests.DNSAnswer{}, votes[0].Err
	}

	qt, err := textToTypeNum(qtype)
	if err != nil {
		return nil, &ResolveError{
			Err:   err.Error(),
			Rcode: 100,
		}
	}

	var ans []requests.DNSAnswer
	for i := 0; i < 3; i++ {
		for _, a := range votes[i].Answers {
			if a.Type != int(qt) {
				continue
			}

			var dup bool
			for _, d := range ans {
				if d.Data == a.Data {
					dup = true
					break
				}
			}
			if dup {
				continue
			}

			found := 1
			var missing Resolver
			for j, v := range votes {
				if j == i {
					continue
				}

				missing = v.Resolver
				for _, o := range v.Answers {
					if o.Type == int(qt) && o.Data == a.Data {
						found++
						missing = nil
						break
					}
				}
			}

			if found == 1 {
				votes[i].Resolver.ReportError()
				continue
			} else if found == 2 && missing != nil {
				missing.ReportError()
			}
			ans = append(ans, a)
		}
	}

	if len(ans) == 0 {
		return ans, &ResolveError{Err: fmt.Sprintf("Resolver Pool: DNS query for %s type %d returned 0 records", name, qt)}
	}
	return ans, nil
}

func (rp *ResolverPool) queryResolver(r Resolver, ch chan *resolveVote, name, qtype string, priority int) {
	var err error
	var again bool
	start := time.Now()
	var ans []requests.DNSAnswer
	var attempts, servfail int

	var maxAttempts, maxFails int
	switch priority {
	case PriorityHigh:
		maxAttempts = 50
		maxFails = 10
	case PriorityLow:
		maxAttempts = 25
		maxFails = 6
	}

	for {
		ans, again, err = r.Resolve(name, qtype)
		if !again {
			break
		} else if priority == PriorityCritical {
			continue
		}

		attempts++
		if attempts > maxAttempts && time.Now().After(start.Add(2*time.Minute)) {
			break
		}
		// Do not allow server failure errors to continue as long
		if (err.(*ResolveError)).Rcode == dns.RcodeServerFailure {
			servfail++
			if servfail > maxFails && time.Now().After(start.Add(time.Minute)) {
				break
			} else if servfail <= (maxFails / 2) {
				time.Sleep(time.Duration(randomInt(1000, 2000)) * time.Millisecond)
			}
		}
	}

	ch <- &resolveVote{
		Err:      err,
		Resolver: r,
		Answers:  ans,
	}
}

func (rp *ResolverPool) numUsableResolvers() int {
	var num int

	for _, r := range rp.Resolvers {
		if r.Available() {
			num++
		}
	}
	return num
}

func randomInt(min, max int) int {
	return min + rand.Intn((max-min)+1)
}

// IsActive returns true if SetActive has been called for the pool within the last 10 seconds.
func (rp *ResolverPool) IsActive() bool {
	rp.activeLock.Lock()
	defer rp.activeLock.Unlock()

	if time.Now().Sub(rp.active) > 10*time.Second {
		return false
	}
	return true
}

// SetActive marks the pool as being active at time.Now() for future checks performed by the IsActive method.
func (rp *ResolverPool) SetActive() {
	rp.activeLock.Lock()
	defer rp.activeLock.Unlock()

	rp.active = time.Now()
}
