// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"sync"

	"github.com/OWASP/Amass/requests"
)

// CurrentScore is an index value into the ScoredResolver.Stats map
const CurrentScore = 128

// ScoredResolver performs DNS queries on a single resolver and maintains a performance score.
type ScoredResolver struct {
	sync.RWMutex
	resolver Resolver
	score    int
	stopped  bool
}

// NewScoredResolver initializes a Resolver that scores the performance of the DNS server.
func NewScoredResolver(res Resolver) *ScoredResolver {
	if res == nil {
		return nil
	}

	return &ScoredResolver{
		resolver: res,
		score:    100,
	}
}

// Stop causes the Resolver to stop.
func (r *ScoredResolver) Stop() error {
	if r.stopped {
		return nil
	}

	r.stopped = true
	return r.resolver.Stop()
}

// Available returns true if the Resolver can handle another DNS request.
func (r *ScoredResolver) Available() bool {
	if r.stopped {
		return false
	}
	return (r.currentScore() >= 50) && r.resolver.Available()
}

// Stats returns performance counters.
func (r *ScoredResolver) Stats() map[int]int64 {
	stats := r.resolver.Stats()

	stats[CurrentScore] = int64(r.currentScore())
	return stats
}

// WipeStats clears the performance counters.
func (r *ScoredResolver) WipeStats() {
	r.resolver.WipeStats()
}

func (r *ScoredResolver) currentScore() int {
	r.RLock()
	defer r.RUnlock()

	return r.score
}

func (r *ScoredResolver) reduceScore() {
	r.Lock()
	defer r.Unlock()

	r.score--
}

// ReportError indicates to the Resolver that it delivered an erroneos response.
func (r *ScoredResolver) ReportError() {
	r.reduceScore()
	r.resolver.ReportError()
}

// Resolve implements the Resolver interface.
func (r *ScoredResolver) Resolve(name, qtype string) ([]requests.DNSAnswer, bool, error) {
	return r.resolver.Resolve(name, qtype)
}

// Reverse implements the Resolver interface.
func (r *ScoredResolver) Reverse(addr string) (string, string, error) {
	return r.resolver.Reverse(addr)
}
