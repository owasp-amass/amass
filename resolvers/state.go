// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// QueryTimeout is the duration until a Resolver query expires.
var QueryTimeout = 5 * time.Second

// ResolveError contains the Rcode returned during the DNS query.
type ResolveError struct {
	Err   string
	Rcode int
}

func (e *ResolveError) Error() string {
	return e.Err
}

type resolveRequest struct {
	ID        uint16
	Timestamp time.Time
	Name      string
	Qtype     uint16
	Msg       *dns.Msg
	Result    chan *resolveResult
}

type resolveResult struct {
	Msg   *dns.Msg
	Again bool
	Err   error
}

func (r *baseResolver) returnRequest(req *resolveRequest, res *resolveResult) {
	req.Result <- res
}

func makeResolveResult(msg *dns.Msg, again bool, err string, rcode int) *resolveResult {
	return &resolveResult{
		Msg:   msg,
		Again: again,
		Err: &ResolveError{
			Err:   err,
			Rcode: rcode,
		},
	}
}

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return &ResolveError{
			Err:   "The request context was cancelled",
			Rcode: ResolverErrRcode,
		}
	default:
	}
	return nil
}

type xchgManager struct {
	sync.Mutex
	xchgs map[string]*resolveRequest
}

func newXchgManager() *xchgManager {
	return &xchgManager{xchgs: make(map[string]*resolveRequest)}
}

func xchgKey(id uint16, name string) string {
	return fmt.Sprintf("%d:%s", id, strings.ToLower(RemoveLastDot(name)))
}

func (r *xchgManager) add(req *resolveRequest) error {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(req.ID, req.Name)
	if _, found := r.xchgs[key]; found {
		return fmt.Errorf("Key %s is already in use", key)
	}

	r.xchgs[key] = req
	return nil
}

func (r *xchgManager) updateTimestamp(id uint16, name string) error {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; !found {
		return fmt.Errorf("A message for key %s was not found", key)
	}

	r.xchgs[key].Timestamp = time.Now()
	return nil
}

func (r *xchgManager) remove(id uint16, name string) *resolveRequest {
	r.Lock()
	defer r.Unlock()

	key := xchgKey(id, name)
	if _, found := r.xchgs[key]; !found {
		return nil
	}

	reqs := r.delete([]string{key})
	if len(reqs) != 1 {
		return nil
	}

	return reqs[0]
}

func (r *xchgManager) removeExpired() []*resolveRequest {
	r.Lock()
	defer r.Unlock()

	now := time.Now()
	var keys []string
	for key, req := range r.xchgs {
		if !req.Timestamp.IsZero() && now.After(req.Timestamp.Add(QueryTimeout)) {
			keys = append(keys, key)
		}
	}

	return r.delete(keys)
}

func (r *xchgManager) removeAll() []*resolveRequest {
	r.Lock()
	defer r.Unlock()

	var keys []string
	for key := range r.xchgs {
		keys = append(keys, key)
	}

	return r.delete(keys)
}

func (r *xchgManager) delete(keys []string) []*resolveRequest {
	var removed []*resolveRequest

	for _, k := range keys {
		req := r.xchgs[k]

		r.xchgs[k] = nil
		delete(r.xchgs, k)
		removed = append(removed, req)
	}

	return removed
}

const (
	minNumInAverage   int     = 25
	maxNumInAverage   int     = 50
	failurePercentage float64 = 0.9
)

type slidingWindowTimeouts struct {
	sync.Mutex
	avgs map[string][]bool
}

func newSlidingWindowTimeouts() *slidingWindowTimeouts {
	return &slidingWindowTimeouts{avgs: make(map[string][]bool)}
}

func (s *slidingWindowTimeouts) updateTimeouts(key string, timeout bool) bool {
	s.Lock()
	defer s.Unlock()

	if _, found := s.avgs[key]; !found {
		s.avgs[key] = []bool{}
	}

	s.avgs[key] = append(s.avgs[key], timeout)

	l := len(s.avgs[key])
	if l < minNumInAverage {
		return false
	}

	if l > maxNumInAverage {
		s.avgs[key] = s.avgs[key][l-maxNumInAverage:]
	}

	var count float64
	for _, v := range s.avgs[key] {
		if v {
			count++
		}
	}

	if count/float64(l) >= failurePercentage {
		return true
	}
	return false
}
