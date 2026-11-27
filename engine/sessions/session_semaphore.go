// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"sync"
	"time"

	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// sessSemaphore limits a session's network connections. The limit is the
// engine's share for the session and changes as other sessions start and
// end, so the channel behind it is replaced. Waiting for a slot happens
// outside the lock: a caller blocked while holding it would keep every
// holder from releasing, and the session would stop for good.
type sessSemaphore struct {
	sync.Mutex
	sem amassnet.Semaphore
}

func NewSessSemaphore(limit int) *sessSemaphore {
	return &sessSemaphore{sem: amassnet.NewSemaphore(limit)}
}

// Acquire waits for a slot. A resize closes the channel being waited on,
// and the caller then waits on the new one.
func (ss *sessSemaphore) Acquire() {
	for {
		ss.Lock()
		sem := ss.sem
		ss.Unlock()

		if _, ok := <-sem; ok {
			return
		}
	}
}

// Release returns a slot. It never blocks, so it holds the lock, which keeps
// it from sending on a channel a resize has closed.
func (ss *sessSemaphore) Release() {
	ss.Lock()
	defer ss.Unlock()

	ss.sem.Release()
}

// resize replaces the semaphore with one of limit slots, less those already
// held, and moves the callers waiting on the old one to it.
func (ss *sessSemaphore) resize(limit int) {
	ss.Lock()
	defer ss.Unlock()

	old := ss.sem
	held := cap(old) - len(old)
	// Drain the old channel so no caller takes a stale slot from it once it
	// is closed; closing it wakes the callers waiting on it. The drain never
	// blocks: a caller may take a slot from it meanwhile.
drain:
	for {
		select {
		case <-old:
		default:
			break drain
		}
	}

	sem := amassnet.NewSemaphore(limit)
	for range min(held, limit) {
		<-sem
	}

	ss.sem = sem
	close(old)
}

func (s *Session) updateSessionSemaphore() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			if num := s.mgr.NumOfSessions(); num != s.numOfSess {
				s.numOfSess = num
				s.buildNewSessionSemaphore()
			}
		}
	}
}

func (s *Session) buildNewSessionSemaphore() {
	s.netSemaphore.resize(sessionConnLimit(s.numOfSess))
}

// sessionConnLimit is a session's share of the engine's network
// connections, at least one so the session can always make progress.
func sessionConnLimit(sessions int) int {
	return max(1, amassnet.MaxNetworkConns/max(1, sessions))
}
