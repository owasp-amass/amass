// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"log/slog"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// BackgroundLane does work beside the pipeline, one job at a time, for work
// a handler must not wait for: an archive that takes an hour to answer for a
// big domain, or a model deciding a name. A pipeline stage waits for its
// handlers, so a handler that waited would stall the run; the handler only
// queues the job. A queued job counts as the session's background work, so
// the run neither finishes before the lane is done with it nor looks idle
// while it works. Each lane has its own worker, so a slow lane never holds
// up another.
type BackgroundLane struct {
	name   string
	budget time.Duration
	once   sync.Once
	wake   chan struct{}
	mu     sync.Mutex
	queue  []backgroundJob
	queued map[string]bool // session and key -> queued or being worked
}

type backgroundJob struct {
	sess   et.Session
	key    string
	plugin string
	what   string
	work   func(context.Context)
}

// NewBackgroundLane returns a lane named for its log entries whose jobs each
// get at most budget.
func NewBackgroundLane(name string, budget time.Duration) *BackgroundLane {
	return &BackgroundLane{name: name, budget: budget, wake: make(chan struct{}, 1), queued: map[string]bool{}}
}

// Enqueue queues work for the session, unless work under the same key is
// already queued for it. plugin and what name the job in the log.
func (l *BackgroundLane) Enqueue(sess et.Session, key, plugin, what string, work func(context.Context)) {
	l.once.Do(func() { go l.run() })

	qk := sess.ID().String() + "|" + key
	l.mu.Lock()
	if l.queued[qk] {
		l.mu.Unlock()
		return
	}
	l.queued[qk] = true
	// counted before the worker can take it, so finishing it never comes first
	sess.Stats().AddBackground(1)
	background.add(sess.ID().String(), 1)
	l.queue = append(l.queue, backgroundJob{sess: sess, key: qk, plugin: plugin, what: what, work: work})
	l.mu.Unlock()

	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// EnqueueAfter queues work for the session as Enqueue does once after has
// passed, unless the session ends first. The wait counts as lane work, so
// the run waits for it no longer than the background hold allows, and a job
// due after the hold has run out is skipped as a queued one is.
func (l *BackgroundLane) EnqueueAfter(sess et.Session, key, plugin, what string, after time.Duration,
	work func(context.Context)) {
	id := sess.ID().String()
	sess.Stats().AddBackground(1)
	background.add(id, 1)
	go func() {
		defer func() {
			// released after the job is queued, so the run never looks done
			// in between
			background.add(id, -1)
			sess.Stats().AddBackground(-1)
		}()

		t := time.NewTimer(after)
		defer t.Stop()
		select {
		case <-sess.Ctx().Done():
			return
		case <-t.C:
		}
		if !sess.Done() {
			l.Enqueue(sess, key, plugin, what, work)
		}
	}()
}

func (l *BackgroundLane) run() {
	for {
		l.mu.Lock()
		if len(l.queue) == 0 {
			l.mu.Unlock()
			<-l.wake
			continue
		}
		j := l.queue[0]
		l.queue = l.queue[1:]
		l.mu.Unlock()

		l.do(j)
	}
}

func (l *BackgroundLane) do(j backgroundJob) {
	sess := j.sess
	defer func() {
		l.mu.Lock()
		delete(l.queued, j.key)
		l.mu.Unlock()
		background.add(sess.ID().String(), -1)
		sess.Stats().DoneBackground(1)
	}()

	if sess.Done() {
		return
	}
	if background.held(sess) {
		sess.Log().Info(l.name+" skipped: the run's other work is done", "item", j.what,
			slog.Group("plugin", "name", j.plugin, "handler", j.plugin+"-Handler"))
		return
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), l.budget)
	defer cancel()
	j.work(ctx)
}

// background tracks every lane's jobs by session, for the background hold.
var background = &backgroundHold{pending: map[string]int{}, settled: map[string]time.Time{}}

type backgroundHold struct {
	mu      sync.Mutex
	pending map[string]int       // session -> its lane jobs not yet done
	settled map[string]time.Time // session -> when it had only lane work left
}

func (b *backgroundHold) add(id string, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pending[id] += n; b.pending[id] <= 0 {
		delete(b.pending, id)
		delete(b.settled, id)
	}
}

// held reports whether the run has had nothing left but lane work for as
// long as its configuration lets background work go on
// (options.background_hold). A job still queued then is left for the next
// run, and the log says so.
func (b *backgroundHold) held(sess et.Session) bool {
	st := sess.Stats()
	st.RLock()
	remaining := st.WorkItemsTotal - st.WorkItemsCompleted
	st.RUnlock()

	id := sess.ID().String()
	b.mu.Lock()
	defer b.mu.Unlock()
	if remaining > b.pending[id] {
		delete(b.settled, id)
		return false
	}
	since, ok := b.settled[id]
	if !ok {
		since = time.Now()
		b.settled[id] = since
	}
	return time.Since(since) >= sess.Config().BackgroundHoldDuration()
}
