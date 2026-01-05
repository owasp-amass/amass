// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/net/publicsuffix"
)

type pipelineInstance struct {
	parent   *pipelinePool
	id       string
	atype    oam.AssetType
	ap       *et.AssetPipeline
	draining atomic.Bool
	queued   atomic.Int64
}

func (pi *pipelineInstance) enqueue(e *et.Event) error {
	if pi.draining.Load() {
		return fmt.Errorf("pipeline instance %s is draining", pi.id)
	}
	pi.queued.Add(1)

	sid := sessionIDOf(e)
	if sid != "" {
		pi.parent.incSessionQueued(sid, 1)
	}

	e.Dispatcher = pi.parent.dis
	data := et.NewEventDataElement(e)
	data.Exit = pi.parent.dis.cchan
	data.Ref = pi // optional: keep a ref to the instance
	return pi.ap.Queue.Append(data)
}

func (pi *pipelineInstance) onDequeue(e *et.Event) {
	pi.queued.Add(-1)

	sid := sessionIDOf(e)
	if sid != "" {
		pi.parent.incSessionQueued(sid, -1)
	}

	if pi.draining.Load() && pi.queueLen() == 0 {
		pi.parent.mu.Lock()
		defer pi.parent.mu.Unlock()

		delete(pi.parent.instances, pi.id)
		pi.parent.log.Info("removed idle pipeline instance",
			"atype", pi.parent.eventTy,
			"id", pi.id,
		)
	}
}

func (pi *pipelineInstance) queueLen() int64 {
	return pi.queued.Load()
}

// ------------------------------------------------------------------------------------------
// ---------------------------------- Pipeline Pool -----------------------------------------
// ------------------------------------------------------------------------------------------

type pipelinePool struct {
	mu           sync.RWMutex
	log          *slog.Logger
	dis          *dynamicDispatcher
	reg          et.Registry
	eventTy      oam.AssetType
	minInstances int
	maxInstances int
	instances    map[string]*pipelineInstance // instanceID -> instance
	ring         *hashRing                    // shardKey -> instanceID
	// session fan-out and load tracking
	sessionFanout map[string]int   // sessionID -> fanout factor (1 = no fanout)
	sessionQueued map[string]int64 // sessionID -> queued count across all instances
	lastScale     time.Time
}

func newPipelinePool(dis *dynamicDispatcher, atype oam.AssetType, min, max int) *pipelinePool {
	if min <= 0 {
		min = 1
	}
	if max < min {
		max = min
	}
	return &pipelinePool{
		log:           dis.log,
		dis:           dis,
		reg:           dis.reg,
		eventTy:       atype,
		minInstances:  min,
		maxInstances:  max,
		instances:     make(map[string]*pipelineInstance),
		ring:          newHashRing(50),
		sessionFanout: make(map[string]int),
		sessionQueued: make(map[string]int64),
		lastScale:     time.Now(),
	}
}

// Dispatch routes the event to an instance based on a session-aware shardKey.
func (p *pipelinePool) Dispatch(e *et.Event) error {
	p.ensureMinInstances()

	// attempt the process again if selection fails
	for i := range 2 {
		shardKey := p.workShardKey(e)
		inst := p.pickInstance(shardKey)
		if inst == nil {
			return fmt.Errorf("no pipeline instance available for %v", p.eventTy)
		}

		if err := inst.enqueue(e); err != nil {
			if i == 0 {
				continue
			}
			return err
		}
		break
	}

	p.maybeScale()
	p.maybeAdjustFanout(e)
	return nil
}

func (p *pipelinePool) ensureMinInstances() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for len(p.instances) < p.minInstances {
		p.createInstanceLocked()
	}
}

// workShardKey decides which logical shard this event belongs to.
// - Normal case (fanout=1): shardKey = sessionID
// - Fan-out case (fanout>1): shardKey = sessionID/bucket, bucket chosen by assetKey.
func (p *pipelinePool) workShardKey(e *et.Event) string {
	sid := sessionIDOf(e)
	if sid == "" {
		// Fallback sharding when we don't have a session
		return fallbackShardKey(e)
	}

	p.mu.RLock()
	fanout := p.sessionFanout[sid]
	p.mu.RUnlock()

	if fanout <= 1 {
		return sid
	}

	assetKey := assetKeyOf(e) // e.g., fqdn, IP, ASN; see helper below
	if assetKey == "" {
		assetKey = sid
	}

	bucket := hashKey(sid+"/"+assetKey) % uint32(fanout)
	return fmt.Sprintf("%s/%d", sid, bucket)
}

// pickInstance enforces "one pipeline per (assetType, shardKey) at a time".
func (p *pipelinePool) pickInstance(shardKey string) *pipelineInstance {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.instances) == 0 {
		return nil
	}

	if shardKey == "" {
		// fallback: pick emptiest
		var best *pipelineInstance
		for _, inst := range p.instances {
			if best == nil || inst.queueLen() < best.queueLen() {
				best = inst
			}
		}
		return best
	}

	id, ok := p.ring.Lookup(shardKey)
	if !ok {
		return nil
	}

	inst, ok := p.instances[id]
	if !ok {
		return nil
	}
	return inst
}

func (p *pipelinePool) createInstanceLocked() *pipelineInstance {
	if len(p.instances) >= p.maxInstances {
		return nil
	}

	ap, err := p.reg.BuildAssetPipeline(string(p.eventTy))
	if err != nil {
		p.log.Error("BuildAssetPipeline failed", "atype", p.eventTy, "err", err)
		return nil
	}

	id := fmt.Sprintf("%s-%d", p.eventTy, len(p.instances)+1)
	inst := &pipelineInstance{
		parent: p,
		id:     id,
		atype:  p.eventTy,
		ap:     ap,
	}
	p.instances[id] = inst
	p.ring.Add(id)

	p.log.Info("created pipeline instance",
		"atype", p.eventTy,
		"id", id,
	)
	return inst
}

// incSessionQueued tracks total queued items for a session across instances.
func (p *pipelinePool) incSessionQueued(sid string, delta int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sessionQueued[sid] += delta
	if p.sessionQueued[sid] <= 0 {
		delete(p.sessionQueued, sid)
	}
}

// maybeAdjustFanout bumps fan-out for very heavy sessions.
func (p *pipelinePool) maybeAdjustFanout(e *et.Event) {
	sid := sessionIDOf(e)
	if sid == "" {
		return
	}

	const (
		sessionGrowThreshold = int64(500)
	)

	p.mu.Lock()
	defer p.mu.Unlock()

	queued := p.sessionQueued[sid]
	if queued <= sessionGrowThreshold {
		p.sessionFanout[sid] = 1
		return
	}

	var scount int
	for _, sess := range p.sessionQueued {
		if sess > 0 {
			scount++
		}
	}
	if scount == 0 {
		return
	}

	n := len(p.instances)
	if n < scount {
		// not enough instances to bother with fan-out
		p.sessionFanout[sid] = 1
		return
	}
	maxFanout := n / scount

	fanout := p.sessionFanout[sid]
	if fanout == 0 {
		fanout = 1
	}

	newFanout := fanout * 2
	if newFanout > maxFanout {
		newFanout = maxFanout
	}
	p.sessionFanout[sid] = newFanout

	p.log.Info("adjusting session fan-out",
		"atype", p.eventTy,
		"session", sid,
		"from", fanout,
		"to", newFanout,
		"queued", queued,
	)
}

// maybeScale still does global instance scaling based on overall queue sizes.
func (p *pipelinePool) maybeScale() {
	const (
		scaleInterval   = 5 * time.Second
		growThreshold   = 100 // avg queued across instances
		shrinkThreshold = 10  // avg queued across instances
	)

	now := time.Now()
	if now.Sub(p.lastScale) < scaleInterval {
		return
	}
	p.lastScale = now

	p.mu.Lock()
	defer p.mu.Unlock()

	var total int64
	for _, inst := range p.instances {
		total += inst.queueLen()
	}

	n := len(p.instances)
	if n == 0 {
		return
	}
	avg := total / int64(n)

	// Scale up
	if avg > growThreshold && n < p.maxInstances {
		p.log.Info("scaling up pipeline pool",
			"atype", p.eventTy,
			"from", n,
			"to", n+1,
			"queuedTotal", total,
			"queuedAvg", avg,
		)
		p.createInstanceLocked()
		return
	}

	// Scale down
	if avg < shrinkThreshold && n > p.minInstances {
		var count int
		// pick emptiest instance to drain
		var best *pipelineInstance

		for _, inst := range p.instances {
			if inst.draining.Load() {
				continue
			}

			count++
			if best == nil || inst.queueLen() < best.queueLen() {
				best = inst
			}
		}
		if best == nil || count <= p.minInstances {
			return
		}

		best.ap.Queue.Drain()
		p.ring.Remove(best.id)
		best.draining.Store(true)
		if best.queueLen() == 0 {
			delete(p.instances, best.id)
			p.log.Info("removed idle pipeline instance",
				"atype", p.eventTy,
				"id", best.id,
			)
		}
	}
}

// ----------------------------------------------------------------
// ---------------- Helpers for session keys ----------------------
// ----------------------------------------------------------------

// sessionIDOf extracts a stable session identifier from an event.
func sessionIDOf(e *et.Event) string {
	if e == nil || e.Session == nil {
		return ""
	}
	// Adjust based on your session type API
	return e.Session.ID().String()
}

// fallbackShardKey is used when we don't have a session; you can
// make this smarter if needed.
func fallbackShardKey(e *et.Event) string {
	if e == nil || e.Entity == nil {
		return ""
	}
	return e.Entity.ID
}

// assetKeyOf returns a stable per-asset key used to choose a bucket
// within a session. This should be consistent with the AssetType.
func assetKeyOf(e *et.Event) string {
	if e == nil || e.Entity == nil {
		return ""
	}

	switch e.Entity.Asset.AssetType() {
	case oam.FQDN:
		if name := e.Entity.Asset.Key(); name != "" {
			if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err != nil {
				return dom
			}
		}
	}

	return e.Entity.Asset.Key()
}
