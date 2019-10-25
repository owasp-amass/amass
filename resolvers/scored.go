// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"sync"

	"github.com/OWASP/Amass/v3/requests"
)

const (
	// CurrentScore is an index value into the ScoredResolver.Stats map.
	CurrentScore = 128

	// PassingScore is the minimum score required to continue use of the Resolver.
	PassingScore = 50
)

// ScoredResolver performs DNS queries on a single resolver and maintains a performance score.
type ScoredResolver struct {
	sync.RWMutex
	resolver Resolver
	score    int
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
	if r.IsStopped() {
		return nil
	}

	return r.resolver.Stop()
}

// IsStopped implements the Resolver interface.
func (r *ScoredResolver) IsStopped() bool {
	return r.resolver.IsStopped()
}

// Address implements the Resolver interface.
func (r *ScoredResolver) Address() string {
	return r.resolver.Address()
}

// Port implements the Resolver interface.
func (r *ScoredResolver) Port() int {
	return r.resolver.Port()
}

// Available returns true if the Resolver can handle another DNS request.
func (r *ScoredResolver) Available() (bool, error) {
	if r.IsStopped() {
		msg := fmt.Sprintf("Resolver %s has been stopped", r.Address())

		return false, &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	if r.currentScore() < PassingScore {
		msg := fmt.Sprintf("Resolver %s has a low score of %d", r.Address(), r.currentScore())

		return false, &ResolveError{
			Err:   msg,
			Rcode: NotAvailableRcode,
		}
	}

	return r.resolver.Available()
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
	if r.score > 0 {
		r.score--
	}
	r.Unlock()

	if r.currentScore() < PassingScore {
		r.Stop()
	}
}

// ReportError indicates to the Resolver that it delivered an erroneos response.
func (r *ScoredResolver) ReportError() {
	r.reduceScore()
	r.resolver.ReportError()
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (r *ScoredResolver) MatchesWildcard(ctx context.Context, req *requests.DNSRequest) bool {
	return r.resolver.MatchesWildcard(ctx, req)
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (r *ScoredResolver) GetWildcardType(ctx context.Context, req *requests.DNSRequest) int {
	return r.resolver.GetWildcardType(ctx, req)
}

// SubdomainToDomain returns the first subdomain name of the provided
// parameter that responds to a DNS query for the NS record type.
func (r *ScoredResolver) SubdomainToDomain(name string) string {
	return r.resolver.SubdomainToDomain(name)
}

// Resolve implements the Resolver interface.
func (r *ScoredResolver) Resolve(ctx context.Context, name, qtype string, priority int) ([]requests.DNSAnswer, bool, error) {
	if avail, err := r.Available(); !avail {
		return []requests.DNSAnswer{}, true, err
	}

	return r.resolver.Resolve(ctx, name, qtype, priority)
}

// Reverse implements the Resolver interface.
func (r *ScoredResolver) Reverse(ctx context.Context, addr string, priority int) (string, string, error) {
	if avail, err := r.Available(); !avail {
		return "", "", err
	}

	return r.resolver.Reverse(ctx, addr, priority)
}
