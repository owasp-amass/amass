// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

func (p *pipelinePool) activeSessionCount(stats sessStatsMap) int {
	set := make(map[string]struct{}, len(stats))

	for sid, sess := range stats {
		if sess.Queued > 0 || sess.Leased > 0 {
			set[sid] = struct{}{}
		}
	}

	return len(set)
}

func (p *pipelinePool) recomputeBoundsLocked(active int) {
	// If nothing is active, drift back toward baseline.
	if active == 0 {
		p.minInstances = p.baseMin
		p.maxInstances = p.baseMax
		return
	}

	// Dynamic max: baseline plus ability to grow with activity/pressure.
	targetMax := max(active, p.baseMax)
	targetMax = clampInt(targetMax, p.baseMin, p.hardMax)

	// Dynamic min: keep some warm capacity as sessions grow (but not 1:1).
	warm := p.baseMin + (active+3)/4 // 1 extra instance per 4 active sessions
	targetMin := clampInt(warm, p.baseMin, targetMax)

	p.minInstances = targetMin
	p.maxInstances = targetMax
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// maybeAdjustFanout bumps fan-out for very heavy sessions.
func (p *pipelinePool) maybeAdjustFanout(stats sessStatsMap) {
	var scount int

	for _, sess := range stats {
		if sess.Leased > 0 {
			scount++
		}
	}
	if scount == 0 {
		return
	}

	p.Lock()
	defer p.Unlock()

	n := len(p.instances)
	for sid, sess := range stats {
		if n < scount || sess.Leased <= 0 {
			// inactive, or not enough instances to bother with fan-out
			p.sessionFanout[sid] = 1
			continue
		}
		maxFanout := n / scount

		fanout := p.sessionFanout[sid]
		fanout = max(fanout, 1)

		newFanout := fanout * 2
		newFanout = min(newFanout, maxFanout)
		if newFanout != fanout {
			p.sessionFanout[sid] = newFanout

			queued := sess.Leased
			p.log.Info("adjusting session fan-out",
				"atype", p.eventTy,
				"session", sid,
				"from", fanout,
				"to", newFanout,
				"queued", queued,
			)
		}
	}
}

// maybeScale still does global instance scaling based on overall queue sizes.
func (p *pipelinePool) maybeScale(stats sessStatsMap) bool {
	p.Lock()
	defer p.Unlock()

	active := p.activeSessionCount(stats)
	// adjust min/max based on active sessions
	p.recomputeBoundsLocked(active)
	// enforce dynamic min immediately
	p.ensureMinInstancesLocked()

	// compute total elements in work queues
	var total int64
	for _, inst := range p.instances {
		total += inst.queueLen()
	}

	n := len(p.instances)
	if n == 0 {
		return false
	}
	avg := total / int64(n)

	// Scale up (within dynamic max)
	if avg > p.limits.HighWater && n < p.maxInstances {
		p.log.Info("scaling up pipeline pool",
			"atype", p.eventTy,
			"from", n,
			"to", n+1,
			"queuedTotal", total,
			"queuedAvg", avg,
			"min", p.minInstances,
			"max", p.maxInstances,
		)
		_ = p.createInstanceLocked()
		return true
	}

	// Scale down (respect dynamic min)
	if avg < p.limits.LowWater && n > p.minInstances {
		var count int
		var best *pipelineInstance

		for _, inst := range p.instances {
			if inst.draining.Load() {
				continue
			}

			count++
			if best == nil || inst.queued.Load() < best.queued.Load() {
				best = inst
			}
		}
		if best == nil || count <= p.minInstances {
			return false
		}

		best.ap.Queue.Drain()
		p.ring.Remove(best.id)
		best.draining.Store(true)
		if best.queued.Load() == 0 {
			delete(p.instances, best.id)
			p.log.Info("removed idle pipeline instance",
				"atype", p.eventTy,
				"id", best.id,
			)
		}

		return true
	}

	return false
}
