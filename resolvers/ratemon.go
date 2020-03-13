// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/requests"
)

const (
	// CurrentRate is an index value into the RateLimitedResolver.Stats map
	CurrentRate = 256

	defaultMaxSlack    = -2 * time.Second
	initialRate        = 10 * time.Millisecond
	defaultRateChange  = 1 * time.Millisecond
	defaultSlowestRate = 25 * time.Millisecond
	defaultFastestRate = time.Millisecond
)

// RateMonitoredResolver performs DNS queries on a single resolver at the rate it can handle.
type RateMonitoredResolver struct {
	sync.RWMutex
	Done     chan struct{}
	resolver Resolver
	last     time.Time
	rate     time.Duration
	counter  time.Duration
}

// NewRateMonitoredResolver initializes a Resolver that scores the performance of the DNS server.
func NewRateMonitoredResolver(res Resolver) *RateMonitoredResolver {
	if res == nil {
		return nil
	}

	r := &RateMonitoredResolver{
		Done:     make(chan struct{}, 2),
		resolver: res,
		last:     time.Now(),
		rate:     initialRate,
	}

	go r.monitorPerformance()
	return r
}

// Stop causes the Resolver to stop.
func (r *RateMonitoredResolver) Stop() error {
	if r.IsStopped() {
		return nil
	}

	close(r.Done)
	return r.resolver.Stop()
}

// IsStopped implements the Resolver interface.
func (r *RateMonitoredResolver) IsStopped() bool {
	return r.resolver.IsStopped()
}

// Address implements the Resolver interface.
func (r *RateMonitoredResolver) Address() string {
	return r.resolver.Address()
}

// Port implements the Resolver interface.
func (r *RateMonitoredResolver) Port() int {
	return r.resolver.Port()
}

// Available returns true if the Resolver can handle another DNS request.
func (r *RateMonitoredResolver) Available() (bool, error) {
	if r.IsStopped() {
		msg := fmt.Sprintf("Resolver %s has been stopped", r.Address())

		return false, &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	if !r.leakyBucket() {
		msg := fmt.Sprintf("Resolver %s has exceeded the rate limit", r.Address())

		return false, &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	return r.resolver.Available()
}

// Stats returns performance counters.
func (r *RateMonitoredResolver) Stats() map[int]int64 {
	stats := r.resolver.Stats()

	stats[CurrentRate] = int64(r.getRate())
	return stats
}

// WipeStats clears the performance counters.
func (r *RateMonitoredResolver) WipeStats() {
	r.resolver.WipeStats()
	r.setRate(initialRate)
}

// ReportError indicates to the Resolver that it delivered an erroneos response.
func (r *RateMonitoredResolver) ReportError() {
	r.resolver.ReportError()
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (r *RateMonitoredResolver) MatchesWildcard(ctx context.Context, req *requests.DNSRequest) bool {
	return r.resolver.MatchesWildcard(ctx, req)
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (r *RateMonitoredResolver) GetWildcardType(ctx context.Context, req *requests.DNSRequest) int {
	return r.resolver.GetWildcardType(ctx, req)
}

// SubdomainToDomain returns the first subdomain name of the provided
// parameter that responds to a DNS query for the NS record type.
func (r *RateMonitoredResolver) SubdomainToDomain(name string) string {
	return r.resolver.SubdomainToDomain(name)
}

// Resolve implements the Resolver interface.
func (r *RateMonitoredResolver) Resolve(ctx context.Context, name, qtype string, priority int) ([]requests.DNSAnswer, bool, error) {
	if r.IsStopped() {
		msg := fmt.Sprintf("Resolver %s has been stopped", r.Address())

		return []requests.DNSAnswer{}, true, &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	return r.resolver.Resolve(ctx, name, qtype, priority)
}

// Reverse implements the Resolver interface.
func (r *RateMonitoredResolver) Reverse(ctx context.Context, addr string, priority int) (string, string, error) {
	if r.IsStopped() {
		msg := fmt.Sprintf("Resolver %s has been stopped", r.Address())

		return "", "", &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	return r.resolver.Reverse(ctx, addr, priority)
}

// Implementation of the leaky bucket algorithm.
func (r *RateMonitoredResolver) leakyBucket() bool {
	r.Lock()
	defer r.Unlock()

	now := time.Now()
	aux := r.counter - now.Sub(r.last)

	if aux > r.rate {
		return false
	}

	if aux < 0 {
		aux = 0
	}

	r.counter = aux + r.rate
	r.last = now
	return true
}

func (r *RateMonitoredResolver) monitorPerformance() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	m := time.NewTicker(time.Minute)
	defer m.Stop()

	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			r.calcRate()
		case <-m.C:
			rate := r.getRate()
			r.WipeStats()
			r.setRate(rate)
		}
	}
}

func (r *RateMonitoredResolver) calcRate() {
	stats := r.Stats()
	rate := time.Duration(stats[CurrentRate])

	attempts := stats[QueryAttempts]
	// There needs to be some data to work with first
	if attempts < 1000 {
		return
	}

	timeouts := stats[QueryTimeouts]
	// Check if too many attempts are being made
	if comp := stats[QueryCompletions]; comp > 0 &&
		comp > timeouts && attempts > (2*(comp-timeouts)) {
		r.setRate(rate + defaultRateChange)
		return
	}
	// Speed things up!
	r.setRate(rate - defaultRateChange)
}

func (r *RateMonitoredResolver) getLast() time.Time {
	r.RLock()
	defer r.RUnlock()

	return r.last
}

func (r *RateMonitoredResolver) setLast(t time.Time) {
	r.Lock()
	defer r.Unlock()

	if t.After(r.last) {
		r.last = t
	}
}

func (r *RateMonitoredResolver) getRate() time.Duration {
	r.RLock()
	defer r.RUnlock()

	return r.rate
}

func (r *RateMonitoredResolver) setRate(d time.Duration) {
	r.Lock()
	defer r.Unlock()

	if d >= defaultFastestRate && d <= defaultSlowestRate {
		r.rate = d
	}
}
