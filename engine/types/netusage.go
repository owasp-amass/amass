// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// NetUsage counts one session's use of the capacity every session of the
// engine shares: DNS queries through the shared resolver pool, and time
// spent waiting on the data sources' rate limits. Comparing sessions shows
// whether each gets its share. The counters are carried in the session's
// context, so the code that queries needs no session.
type NetUsage struct {
	mu    sync.Mutex
	dns   DNSUsage
	waits map[string]*WaitUsage
	// maxWaits bounds the rate limits counted; zero is maxWaitSources.
	maxWaits int
}

// DNSUsage counts a session's DNS queries; Took includes the time a query
// waited for the resolver pool.
type DNSUsage struct {
	Queries  int
	Answered int
	NoRecord int
	Failed   int
	Took     time.Duration
}

// WaitUsage counts a session's waits on one rate limit.
type WaitUsage struct {
	Waits int
	Took  time.Duration
}

// maxWaitSources bounds the rate limits counted per session.
const maxWaitSources = 256

// DNS outcomes for NetUsage.DNSQuery.
const (
	DNSAnswered = iota
	DNSNoRecord
	DNSFailed
)

type netUsageKey struct{}

// WithNetUsage returns ctx carrying u.
func WithNetUsage(ctx context.Context, u *NetUsage) context.Context {
	return context.WithValue(ctx, netUsageKey{}, u)
}

// NetUsageFrom returns the counters ctx carries, or nil; a nil NetUsage
// counts nothing.
func NetUsageFrom(ctx context.Context) *NetUsage {
	if ctx == nil {
		return nil
	}

	u, _ := ctx.Value(netUsageKey{}).(*NetUsage)
	return u
}

// DNSQuery records one query, its outcome and how long it took.
func (u *NetUsage) DNSQuery(outcome int, took time.Duration) {
	if u == nil {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	u.dns.Queries++
	u.dns.Took += took
	switch outcome {
	case DNSAnswered:
		u.dns.Answered++
	case DNSNoRecord:
		u.dns.NoRecord++
	default:
		u.dns.Failed++
	}
}

// Waited records time spent waiting on the named rate limit.
func (u *NetUsage) Waited(source string, took time.Duration) {
	if u == nil {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.waits == nil {
		u.waits = map[string]*WaitUsage{}
	}

	w, ok := u.waits[source]
	if !ok {
		max := u.maxWaits
		if max == 0 {
			max = maxWaitSources
		}
		if len(u.waits) >= max {
			source = "other"
			if w, ok = u.waits[source]; !ok {
				w = &WaitUsage{}
				u.waits[source] = w
			}
		} else {
			w = &WaitUsage{}
			u.waits[source] = w
		}
	}

	w.Waits++
	w.Took += took
}

// DNS returns the DNS counts so far.
func (u *NetUsage) DNS() DNSUsage {
	if u == nil {
		return DNSUsage{}
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	return u.dns
}

// Waits returns the rate limit waits so far, by source.
func (u *NetUsage) Waits() map[string]WaitUsage {
	out := map[string]WaitUsage{}
	if u == nil {
		return out
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	for s, w := range u.waits {
		out[s] = *w
	}

	return out
}

// Log writes the counts so far: one line for DNS and one per rate limit
// waited on, the longest waits first.
func (u *NetUsage) Log(l *slog.Logger, msg string) {
	if u == nil || l == nil {
		return
	}

	d := u.DNS()
	mean := time.Duration(0)
	if d.Queries > 0 {
		mean = d.Took / time.Duration(d.Queries)
	}

	l.Info(msg, "dns_queries", d.Queries, "dns_answered", d.Answered, "dns_no_record", d.NoRecord,
		"dns_failed", d.Failed, "dns_took", d.Took.Round(time.Millisecond).String(),
		"dns_mean", mean.Round(time.Microsecond).String())

	waits := u.Waits()
	sources := make([]string, 0, len(waits))
	for s := range waits {
		sources = append(sources, s)
	}

	sort.Slice(sources, func(i, j int) bool { return waits[sources[i]].Took > waits[sources[j]].Took })
	for _, s := range sources {
		w := waits[s]
		l.Info(msg+": rate limit waits", "source", s, "waits", w.Waits,
			"took", w.Took.Round(time.Millisecond).String(),
			"mean", (w.Took / time.Duration(w.Waits)).Round(time.Millisecond).String())
	}
}
