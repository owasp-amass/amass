// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/requests"
)

const (
	// CurrentRate is an index value into the RateLimitedResolver.Stats map
	CurrentRate = 256

	initialRate        = 10 * time.Millisecond
	defaultRateChange  = 1 * time.Millisecond
	defaultSlowestRate = 25 * time.Millisecond
	defaultFastestRate = time.Millisecond
)

// RateMonitoredResolver performs DNS queries on a single resolver at the rate it can handle.
type RateMonitoredResolver struct {
	Done         chan struct{}
	resolver     Resolver
	rateChannels *rateChans
}

// NewRateMonitoredResolver initializes a Resolver that scores the performance of the DNS server.
func NewRateMonitoredResolver(res Resolver) *RateMonitoredResolver {
	if res == nil {
		return nil
	}

	r := &RateMonitoredResolver{
		Done:     make(chan struct{}, 2),
		resolver: res,
		rateChannels: &rateChans{
			GetRate:     make(chan chan time.Duration, 10),
			SetRate:     make(chan time.Duration, 10),
			LeakyBucket: make(chan chan bool, 10),
			ResetTimer:  make(chan struct{}, 10),
		},
	}

	go r.manageRateState()
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

// String implements the Stringer interface.
func (r *RateMonitoredResolver) String() string {
	return r.resolver.String()
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

// ReportError indicates to the Resolver that it delivered an erroneous response.
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
		msg := fmt.Sprintf("Resolver %s has been stopped", r.String())

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
		msg := fmt.Sprintf("Resolver %s has been stopped", r.String())

		return "", "", &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	return r.resolver.Reverse(ctx, addr, priority)
}

// NsecTraversal implements the Resolver interface.
func (r *RateMonitoredResolver) NsecTraversal(ctx context.Context, domain string, priority int) ([]string, bool, error) {
	if r.IsStopped() {
		msg := fmt.Sprintf("Resolver %s has been stopped", r.String())

		return []string{}, true, &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	return r.resolver.NsecTraversal(ctx, domain, priority)
}

type rateChans struct {
	GetRate     chan chan time.Duration
	SetRate     chan time.Duration
	LeakyBucket chan chan bool
	ResetTimer  chan struct{}
}

func (r *RateMonitoredResolver) manageRateState() {
	var counter time.Duration
	last := time.Now()
	rate := initialRate
	t := time.NewTimer(time.Second)
	defer t.Stop()
	m := time.NewTicker(time.Minute)
	defer m.Stop()
loop:
	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			go r.calcRate()
		case <-r.rateChannels.ResetTimer:
			t.Reset(time.Second)
		case <-m.C:
			go r.resolver.WipeStats()
		case get := <-r.rateChannels.GetRate:
			get <- rate
		case r := <-r.rateChannels.SetRate:
			if r >= defaultFastestRate && r <= defaultSlowestRate {
				rate = r
			}
		case ch := <-r.rateChannels.LeakyBucket:
			now := time.Now()
			aux := counter - now.Sub(last)

			if aux > rate {
				ch <- false
				continue loop
			}

			if aux < 0 {
				aux = 0
			}
			counter = aux + rate
			last = now
			ch <- true
		}
	}
}

func (r *RateMonitoredResolver) calcRate() {
	defer r.resetTimer()

	stats := r.Stats()
	rate := time.Duration(stats[CurrentRate])
	attempts := stats[QueryAttempts]
	// There needs to be some data to work with first
	if attempts < 50 {
		return
	}

	timeouts := stats[QueryTimeouts]
	// Check if too many attempts are being made
	if comp := stats[QueryCompletions]; comp > 0 && comp > timeouts {
		succ := comp - timeouts
		max := succ + (succ / 10)

		if attempts > max {
			// Slow things down!
			r.setRate(rate + defaultRateChange)
			return
		}
	}
	// Speed things up!
	r.setRate(rate - defaultRateChange)
}

func (r *RateMonitoredResolver) getRate() time.Duration {
	ch := make(chan time.Duration, 2)

	r.rateChannels.GetRate <- ch
	return <-ch
}

func (r *RateMonitoredResolver) setRate(d time.Duration) {
	r.rateChannels.SetRate <- d
}

// Implementation of the leaky bucket algorithm.
func (r *RateMonitoredResolver) leakyBucket() bool {
	ch := make(chan bool, 2)

	r.rateChannels.LeakyBucket <- ch
	return <-ch
}

func (r *RateMonitoredResolver) resetTimer() {
	r.rateChannels.ResetTimer <- struct{}{}
}
