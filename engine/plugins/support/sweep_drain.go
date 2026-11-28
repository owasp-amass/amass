// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// sweepDrainCheck is how often a session's sweep budget checks whether the
// session's other work is done.
const sweepDrainCheck = 5 * time.Second

// SessionDrained reports whether only background work remains in a
// session.
func SessionDrained(stats *et.SessionStats) bool {
	stats.RLock()
	total, completed := stats.WorkItemsTotal, stats.WorkItemsCompleted
	stats.RUnlock()

	return total-completed <= stats.Background()
}

// watch starts, when it is not running, the watcher that removes the dead
// addresses of the session's sweeps once the session's other work is done:
// those swept in the last sweepPruneAge of a run are never reached by the
// removal during the run. It counts as the session's background work, so
// the session is not reported finished first.
func (b *SweepBudget) watch() {
	b.mu.Lock()
	if b.watching || b.sess == nil {
		b.mu.Unlock()
		return
	}
	b.watching = true
	b.mu.Unlock()

	stats := b.sess.Stats()
	stats.AddBackground(1)
	go func() {
		defer stats.AddBackground(-1)
		defer func() {
			b.mu.Lock()
			b.watching = false
			b.mu.Unlock()
		}()

		settled := 0
		tick := time.NewTicker(sweepDrainCheck)
		defer tick.Stop()
		for {
			select {
			case <-b.sess.Ctx().Done():
				return
			case <-tick.C:
			}
			if b.sess.Done() {
				return
			}
			if !SessionDrained(stats) {
				settled = 0
				continue
			}
			if settled++; settled < 2 {
				continue
			}

			ctx, cancel := context.WithTimeout(b.sess.Ctx(), 5*time.Minute)
			b.finish(ctx, b.sess.DB(), b.sess.StartTime(), time.Now())
			cancel()
			return
		}
	}()
}

// finish removes, once the session's other work is done, every swept
// address that showed no hit, at any age: no handler holds one any longer.
func (b *SweepBudget) finish(ctx context.Context, db SweepDB, since, now time.Time) {
	if db == nil {
		return
	}

	b.mu.Lock()
	left := map[string][]string{}
	for cidr, e := range b.nb {
		for addr := range e.pending {
			left[cidr] = append(left[cidr], addr)
		}
		for addr := range e.dead {
			left[cidr] = append(left[cidr], addr)
		}
	}
	b.mu.Unlock()

	for cidr, addrs := range left {
		for _, addr := range addrs {
			if ctx.Err() != nil {
				return
			}
			if sweepAddrConfirmed(ctx, db, addr) {
				continue
			}
			removed := pruneDead(ctx, db, addr, since, now)

			b.mu.Lock()
			if e, ok := b.nb[cidr]; ok {
				delete(e.pending, addr)
				delete(e.dead, addr)
				e.done[addr] = true
				if removed {
					e.gone[addr] = true
				}
			}
			b.mu.Unlock()
		}
	}
}
