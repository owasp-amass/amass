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

	r := &ScoredResolver{
		resolver: res,
		score:    100,
	}

	if !r.SanityCheck() {
		return nil
	}
	return r
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

// SanityCheck performs some basic checks to see if the Resolver will be usable.
func (r *ScoredResolver) SanityCheck() bool {
	f := func(name string, flip bool, ch chan bool) {
		var err error
		again := true
		var success bool

		for i := 0; i < 2 && again; i++ {
			_, again, err = r.Resolve(name, "A")
			if err == nil {
				success = true
				break
			}
		}

		if flip {
			success = !success
		}
		ch <- success
	}

	results := make(chan bool, 10)
	// Check that valid names can be resolved
	goodNames := []string{
		"www.owasp.org",
		"twitter.com",
		"github.com",
		"www.google.com",
	}
	for _, name := range goodNames {
		go f(name, false, results)
	}

	// Check that invalid names do not return false positives
	badNames := []string{
		"not-a-real-name.owasp.org",
		"wwww.owasp.org",
		"www-1.owasp.org",
		"www1.owasp.org",
		"wwww.google.com",
		"www-1.google.com",
		"www1.google.com",
		"not-a-real-name.google.com",
	}
	for _, name := range badNames {
		go f(name, true, results)
	}

	success := true
	l := len(goodNames) + len(badNames)
	for i := 0; i < l; i++ {
		select {
		case succ := <-results:
			if !succ {
				success = false
			}
		}
	}
	return success
}
