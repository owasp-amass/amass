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

	defaultMaxSlack      = -2 * time.Second
	initialRate          = 55 * time.Millisecond
	defaultRateChange    = 10 * time.Millisecond
	defaultMaxFailurePCT = 0.89
	scoredResolverMaxRTT = 1500 * time.Millisecond
)

// RateMonitoredResolver performs DNS queries on a single resolver at the rate it can handle.
type RateMonitoredResolver struct {
	sync.RWMutex
	Done        chan struct{}
	resolver    Resolver
	last        time.Time
	rate        time.Duration
	timeToSleep time.Duration
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

	if time.Now().After(r.getLast().Add(r.getRate())) == false {
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

	r.wait()
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

	r.wait()
	return r.resolver.Reverse(ctx, addr, priority)
}

// Implementation of the leaky bucket algorithm.
func (r *RateMonitoredResolver) wait() {
	now := time.Now()
	last := r.getLast()

	tts := r.getTimeToSleep()
	tts += r.getRate() - now.Sub(last)
	if tts < defaultMaxSlack {
		tts = defaultMaxSlack
	}

	if tts > 0 {
		time.Sleep(tts)
		r.setLast(now.Add(tts))
		r.setTimeToSleep(time.Duration(0))
		return
	}

	r.setLast(now)
	r.setTimeToSleep(tts)
}

func (r *RateMonitoredResolver) monitorPerformance() {
	t := time.NewTicker(3 * time.Second)
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

	if attempts := stats[QueryAttempts]; attempts >= 10 {
		timeouts := stats[QueryTimeout]

		if timeouts >= attempts {
			r.ReportError()
			r.setRate(rate + defaultRateChange)
			return
		}

		// Check if the latency is too high
		if value, found := stats[QueryRTT]; found {
			if rtt := time.Duration(value); rtt > scoredResolverMaxRTT {
				//r.ReportError()
			}
		}

		if pct := float64(timeouts) / float64(attempts); pct > defaultMaxFailurePCT {
			r.setRate(rate + defaultRateChange)
			return
		}
	}

	if rate >= (defaultRateChange + (2 * time.Millisecond)) {
		r.setRate(rate - defaultRateChange)
	}
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

	r.rate = d
}

func (r *RateMonitoredResolver) getTimeToSleep() time.Duration {
	r.RLock()
	defer r.RUnlock()

	return r.timeToSleep
}

func (r *RateMonitoredResolver) setTimeToSleep(d time.Duration) {
	r.Lock()
	defer r.Unlock()

	r.timeToSleep = d
}
