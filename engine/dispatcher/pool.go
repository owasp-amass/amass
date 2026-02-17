// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/net/publicsuffix"
)

type poolLimits struct {
	MaxQueued    int64
	HighWater    int64
	LowWater     int64
	PerSessBurst int64
}

type pipelinePool struct {
	sync.RWMutex
	log     *slog.Logger
	dis     *dynamicDispatcher
	reg     et.Registry
	eventTy oam.AssetType
	// dynamic bounds
	minInstances int
	maxInstances int
	// baseline policy bounds
	baseMin         int
	baseMax         int
	hardMax         int // absolute safety cap
	nextInstanceSeq uint64
	instances       map[string]*pipelineInstance // instanceID -> instance
	ring            *hashRing                    // shardKey -> instanceID
	// session fan-out and load tracking
	sessionFanout map[string]int // sessionID -> fanout factor (1 = no fanout)
	wake          chan struct{}
	limits        *poolLimits
	shuffler      *rand.Rand
}

func newPipelinePool(dis *dynamicDispatcher, atype oam.AssetType, pmin, pmax int) *pipelinePool {
	pmin = max(pmin, 1)
	pmax = max(pmax, pmin)
	hard := pmax * 2

	// Create a new random source
	shuffler := rand.New(rand.NewSource(time.Now().UnixNano()))

	p := &pipelinePool{
		log:           dis.log,
		dis:           dis,
		reg:           dis.reg,
		eventTy:       atype,
		minInstances:  pmin,
		maxInstances:  pmax,
		baseMin:       pmin,
		baseMax:       pmax,
		hardMax:       hard,
		instances:     make(map[string]*pipelineInstance),
		ring:          newHashRing(50),
		sessionFanout: make(map[string]int),
		wake:          make(chan struct{}, 1),
		limits:        limitsByAssetType(atype),
		shuffler:      shuffler,
	}

	p.ensureMinInstances()
	go p.runPump()
	return p
}

// Dispatch wakes up the pump for admission.
func (p *pipelinePool) Dispatch(e *et.Event) error {
	// decide whether to fill work queues
	inst := p.pickInstance(p.workShardKey(e))
	if inst != nil && inst.queueLen() <= p.limits.LowWater {
		p.notifyCapacity()
	}
	return nil
}

func (p *pipelinePool) ensureMinInstances() {
	p.Lock()
	defer p.Unlock()

	p.ensureMinInstancesLocked()
}

func (p *pipelinePool) ensureMinInstancesLocked() {
	for len(p.instances) < p.minInstances {
		if p.createInstanceLocked() == nil {
			break
		}
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

	p.RLock()
	fanout := p.sessionFanout[sid]
	p.RUnlock()

	if fanout <= 1 {
		return sid
	}

	assetKey := assetBucket(e)
	if assetKey == "" {
		assetKey = sid
	}

	bucket := hashKey(sid+"/"+assetKey) % uint32(fanout)
	return fmt.Sprintf("%s/%d", sid, bucket)
}

// pickInstance enforces "one pipeline per (assetType, shardKey) at a time".
func (p *pipelinePool) pickInstance(shardKey string) *pipelineInstance {
	p.RLock()
	defer p.RUnlock()

	if len(p.instances) == 0 {
		return nil
	}

	if shardKey == "" {
		// fallback: pick emptiest
		var best *pipelineInstance
		for _, inst := range p.instances {
			if best == nil || inst.queued.Load() < best.queued.Load() {
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

func (p *pipelinePool) runPump() {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-p.dis.done:
			return
		case <-p.wake:
			p.pumpOnce()
		case <-tick.C:
			p.pumpOnce()
		}
	}
}

func (p *pipelinePool) pumpOnce() {
	stats, err := p.dis.snapshotSessBacklogStats(p.eventTy)
	if err != nil {
		return
	}

	// check that at least one instance has enough capacity
	if !p.hasCapacity(p.limits.PerSessBurst) {
		return
	}

	// build a list of the session IDs
	sessions := make([]string, 0, len(stats))
	for sid := range stats {
		sessions = append(sessions, sid)
	}

	// shuffle the sessions for random selection
	p.shuffler.Shuffle(len(sessions), func(i, j int) {
		sessions[i], sessions[j] = sessions[j], sessions[i]
	})

	for _, sess := range sessions {
		s := stats[sess]
		if s.Queued == 0 {
			// there are zero entities to claim from the backlog
			continue
		}

		entities, err := s.Session.Backlog().ClaimNext(p.eventTy, int(p.limits.PerSessBurst))
		if err != nil {
			continue
		}

		for _, ent := range entities {
			a := ent.Asset
			name := string(a.AssetType()) + ": " + a.Key()
			meta, _ := p.dis.meta.GetEntry(sess, ent.ID)

			event := &et.Event{
				Name:       name,
				Entity:     ent,
				Meta:       meta,
				Dispatcher: p.dis,
				Session:    s.Session,
			}

			inst := p.pickInstance(p.workShardKey(event))
			if inst == nil {
				_ = s.Session.Backlog().Release(ent, p.eventTy, false)
				continue
			}

			if err := inst.enqueue(event); err != nil {
				_ = s.Session.Backlog().Release(ent, p.eventTy, false)
			}
		}
	}
}

func (p *pipelinePool) hasCapacity(num int64) bool {
	p.RLock()
	defer p.RUnlock()

	for _, inst := range p.instances {
		if inst.queueLen()+num <= p.limits.MaxQueued {
			return true
		}
	}
	return false
}

func (p *pipelinePool) notifyCapacity() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// sessionIDOf extracts a stable session identifier from an event.
func sessionIDOf(e *et.Event) string {
	if e == nil || e.Session == nil {
		return ""
	}
	return e.Session.ID().String()
}

// fallbackShardKey is used when we don't have a session.
func fallbackShardKey(e *et.Event) string {
	if e == nil || e.Entity == nil {
		return ""
	}
	return e.Entity.ID
}

// assetKeyOf returns a stable per-asset key used to choose a bucket
// within a session. This should be consistent with the AssetType.
func assetBucket(e *et.Event) string {
	if e == nil || e.Entity == nil {
		return ""
	}

	switch e.Entity.Asset.AssetType() {
	case oam.FQDN:
		if name := e.Entity.Asset.Key(); name != "" {
			if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
				return dom
			}
		}
	}

	return e.Entity.Asset.Key()
}

func limitsByAssetType(atype oam.AssetType) *poolLimits {
	switch atype {
	case oam.FQDN:
		fallthrough
	case oam.IPAddress:
		return &poolLimits{
			MaxQueued:    200,
			HighWater:    175,
			LowWater:     100,
			PerSessBurst: 10,
		}
	case oam.Service:
		fallthrough
	case oam.TLSCertificate:
		fallthrough
	case oam.URL:
		return &poolLimits{
			MaxQueued:    100,
			HighWater:    75,
			LowWater:     25,
			PerSessBurst: 5,
		}
	}

	return &poolLimits{
		MaxQueued:    20,
		HighWater:    15,
		LowWater:     5,
		PerSessBurst: 1,
	}
}
