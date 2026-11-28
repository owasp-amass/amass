// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"strings"
	"sync"
	"time"
)

// GraphChanges is what a store reports changed since a time.
type GraphChanges struct {
	// Now is the store's time when it answered.
	Now time.Time
	// Deletions counts every deletion the store has made; it changes when
	// anything was deleted, merges included.
	Deletions int64
	// IDs are the assets whose rows, relations or properties were created
	// or updated since the time asked about, both ends of a relation
	// included.
	IDs []string
}

// ChangeReader is a graph that reports what changed in its store since a
// time. A zero since reports only Now and Deletions.
type ChangeReader interface {
	GraphChanges(ctx context.Context, since time.Time) (GraphChanges, error)
}

// changeOverlap is how far before the last refresh a refresh asks for
// changes: a write whose transaction commits late can carry an earlier
// time.
const changeOverlap = time.Minute

// LastingCache keeps one cached graph (Cached) across requests, such as an
// enumeration's repeated attribution passes over the same footprint. Before
// each request, Refresh asks the store what changed: anything deleted
// starts the cache over, and otherwise only what the cache holds about the
// changed assets is dropped. It is not safe for requests that run at the
// same time as a Refresh.
type LastingCache struct {
	inner     Graph
	mu        sync.Mutex
	cache     *cachedGraph
	since     time.Time
	deletions int64
}

// NewLastingCache returns a lasting cache over g.
func NewLastingCache(g Graph) *LastingCache {
	return &LastingCache{inner: g}
}

// Refresh brings the cache up to date with the store and returns the graph
// to read. When the store cannot report its changes, or the report fails,
// it returns a cache for this request alone with the error, and the next
// Refresh starts over.
func (l *LastingCache) Refresh(ctx context.Context) (Graph, error) {
	cr, okc := l.inner.(ChangeReader)
	full, okf := l.inner.(fullGraph)
	if !okc || !okf {
		return Cached(l.inner), ErrUnsupported
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var since time.Time
	if l.cache != nil {
		since = l.since.Add(-changeOverlap)
	}

	ch, err := cr.GraphChanges(ctx, since)
	if err != nil {
		l.cache = nil
		return Cached(l.inner), err
	}

	if l.cache == nil || ch.Deletions != l.deletions {
		l.cache = &cachedGraph{inner: full, entries: map[string]any{}}
	} else {
		l.cache.forget(ch.IDs)
	}

	l.since, l.deletions = ch.Now, ch.Deletions
	return l.cache, nil
}

// forget drops what the cache holds about ids: their assets, relations and
// evidence. Relation evidence is kept by relation rather than by asset, so
// any change drops all of it.
func (c *cachedGraph) forget(ids []string) {
	if len(ids) == 0 {
		return
	}

	gone := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		gone[id] = struct{}{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		kind, rest, _ := strings.Cut(key, "\x00")
		if kind == "x" {
			delete(c.entries, key)
			continue
		}

		id, _, _ := strings.Cut(rest, "\x00")
		if _, ok := gone[id]; ok {
			delete(c.entries, key)
		}
	}
}
