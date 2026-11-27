// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// DefaultModelFailures is how many requests in a row the main model may fail
// before a session stops asking it.
const DefaultModelFailures = 3

// ModelBreaker stops a session asking the main model once it has failed
// several requests in a row (unreachable, refusing, timing out), so a run is
// not held open waiting out a timeout for every decision. What the model
// would have decided is left to the rules and to review, as with no model.
// A reply the model gave but that cannot be used is not a failure, and nor
// is a request cut short because the session ended. It is shared by the
// session's deciders and is safe for concurrent use; a nil breaker never
// stops anything.
type ModelBreaker struct {
	// Limit is the failures in a row that stop it; 0 uses
	// DefaultModelFailures.
	Limit int
	// OnOpen, when set, is told once, with the last failure, when the
	// breaker stops the model.
	OnOpen func(err error)

	mu       sync.Mutex
	failures int
	open     bool
	// requests counts the requests recorded, failed ones included.
	requests atomic.Int64
}

// ErrModelStopped is returned in place of asking a model the session stopped
// asking.
var ErrModelStopped = errors.New("the main model failed repeatedly and is not asked again in this run")

// Allow reports whether the model may still be asked.
func (b *ModelBreaker) Allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.open
}

// Requests is how many requests the model was sent, by every decider
// sharing the breaker: each is recorded, whatever its outcome.
func (b *ModelBreaker) Requests() int64 {
	if b == nil {
		return 0
	}
	return b.requests.Load()
}

// Record notes the outcome of a request: success resets the count, and a
// failure counts toward the limit.
func (b *ModelBreaker) Record(err error) {
	if b == nil {
		return
	}
	b.requests.Add(1)
	if errors.Is(err, context.Canceled) {
		return
	}

	b.mu.Lock()
	if err == nil {
		b.failures = 0
		b.mu.Unlock()
		return
	}
	b.failures++
	limit := b.Limit
	if limit <= 0 {
		limit = DefaultModelFailures
	}
	opened := !b.open && b.failures >= limit
	if opened {
		b.open = true
	}
	b.mu.Unlock()

	if opened && b.OnOpen != nil {
		b.OnOpen(fmt.Errorf("%d requests in a row failed, the last: %w", limit, err))
	}
}
