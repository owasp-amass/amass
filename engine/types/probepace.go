// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// ProbePacer spaces active-enumeration probes to the same destination host.
// Several probes (HTTP across many ports, SSH, mail and file greetings) may
// reach one address at once, and a burst of connections to many ports of
// one host in a moment is what a firewall fingerprints as a port scan. The
// pacer holds each probe until a bounded, randomized interval has passed
// since the previous probe to that same host, so the connections are spread
// over time and arrive in no fixed order.
//
// It paces each host on its own: probes to different hosts never wait on one
// another, so an enumeration with many hosts in flight keeps its throughput.
// The pacer only ever delays a probe, never skips one and never adds a
// request, so accuracy is unchanged and no extra load reaches the host. It
// is a courtesy to the hosts being examined, not a way to hide the probes:
// an operator examining their own attack surface can still allow Amass
// through their own controls.
type ProbePacer struct {
	mu   sync.Mutex
	next map[string]time.Time
	min  time.Duration
	span time.Duration
	rng  *rand.Rand
}

// probePacerKey carries a ProbePacer on a context.
type probePacerKey struct{}

// maxPacedHosts bounds the hosts a pacer remembers. An endless enumeration
// reaches many hosts, so entries no longer imposing a wait are dropped once
// the map passes this size, which keeps its memory bounded.
const maxPacedHosts = 8192

// NewProbePacer returns a pacer that holds each host's probes at least min
// apart, with up to span of added random spread. A min of zero disables
// pacing. span is clamped to at least zero.
func NewProbePacer(min, span time.Duration) *ProbePacer {
	if min <= 0 {
		return nil
	}
	if span < 0 {
		span = 0
	}

	return &ProbePacer{
		next: make(map[string]time.Time),
		min:  min,
		span: span,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Pace blocks until this probe to host may proceed, then reserves the next
// slot for host. A nil pacer, an empty host or an already-cancelled context
// returns at once. It returns the context's error if it is cancelled while
// waiting, so a stopped session never stays blocked.
func (p *ProbePacer) Pace(ctx context.Context, host string) error {
	if p == nil || host == "" {
		return nil
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	wait := p.reserve(host)
	if wait <= 0 {
		return nil
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	if ctx == nil {
		<-timer.C
		return nil
	}

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// reserve records that host is probed next after the current reservation
// and returns how long the caller must wait first.
func (p *ProbePacer) reserve(host string) time.Duration {
	gap := p.min
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.span > 0 {
		gap += time.Duration(p.rng.Int63n(int64(p.span)))
	}

	now := time.Now()
	start := now
	if at, ok := p.next[host]; ok && at.After(now) {
		start = at
	}

	p.next[host] = start.Add(gap)
	if len(p.next) > maxPacedHosts {
		p.prune(now)
	}

	return start.Sub(now)
}

// prune drops hosts whose reserved time has passed, since they no longer
// delay a later probe. The caller holds the lock.
func (p *ProbePacer) prune(now time.Time) {
	for host, at := range p.next {
		if !at.After(now) {
			delete(p.next, host)
		}
	}
}

// WithProbePacer returns ctx carrying p.
func WithProbePacer(ctx context.Context, p *ProbePacer) context.Context {
	return context.WithValue(ctx, probePacerKey{}, p)
}

// ProbePacerFrom returns the pacer ctx carries, or nil; a nil pacer paces
// nothing.
func ProbePacerFrom(ctx context.Context) *ProbePacer {
	if ctx == nil {
		return nil
	}

	p, _ := ctx.Value(probePacerKey{}).(*ProbePacer)
	return p
}
