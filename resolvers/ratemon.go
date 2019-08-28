// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"sync"
	"time"

	"github.com/OWASP/Amass/requests"
)

const (
	// CurrentRate is an index value into the RateLimitedResolver.Stats map
	CurrentRate = 256

	defaultMaxSlack      = -2 * time.Second
	initialRate          = 55 * time.Millisecond
	defaultRateChange    = 10 * time.Millisecond
	defaultMaxFailurePCT = 0.50
	scoredResolverMaxRTT = time.Second
)

// RateMonitoredResolver performs DNS queries on a single resolver at the rate it can handle.
type RateMonitoredResolver struct {
	sync.RWMutex
	Done        chan struct{}
	resolver    Resolver
	last        time.Time
	rate        time.Duration
	timeToSleep time.Duration
	stopped     bool
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
	if r.stopped {
		return nil
	}

	r.stopped = true
	close(r.Done)
	return r.resolver.Stop()
}

// Available returns true if the Resolver can handle another DNS request.
func (r *RateMonitoredResolver) Available() bool {
	if r.stopped || !r.resolver.Available() {
		return false
	}

	var avail bool
	if time.Now().After(r.getLast().Add(r.getRate())) {
		avail = true
	}
	return avail
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

// Resolve implements the Resolver interface.
func (r *RateMonitoredResolver) Resolve(name, qtype string) ([]requests.DNSAnswer, bool, error) {
	r.wait()
	return r.resolver.Resolve(name, qtype)
}

// Reverse implements the Resolver interface.
func (r *RateMonitoredResolver) Reverse(addr string) (string, string, error) {
	r.wait()
	return r.resolver.Reverse(addr)
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

	attempts := stats[QueryAttempts]
	if attempts < 10 {
		return
	}

	timeouts := stats[QueryTimeout]
	rate := time.Duration(stats[CurrentRate])
	if timeouts >= attempts {
		r.ReportError()
		r.setRate(rate + defaultRateChange)
		return
	}

	// Check if the latency is too high
	if value, found := stats[QueryRTT]; found {
		if rtt := time.Duration(value); rtt > scoredResolverMaxRTT {
			r.ReportError()
		}
	}

	if pct := float64(timeouts) / float64(attempts); pct > defaultMaxFailurePCT {
		r.setRate(rate + defaultRateChange)
		return
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

	r.last = t
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
