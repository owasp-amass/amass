// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/caffix/queue"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type dynamicDispatcher struct {
	sync.RWMutex
	log    *slog.Logger
	reg    et.Registry
	mgr    et.SessionManager
	done   chan struct{}
	cqueue queue.Queue
	cchan  chan *et.EventDataElement
	pools  map[oam.AssetType]*pipelinePool
	meta   *metaMap
}

func NewDispatcher(l *slog.Logger, r et.Registry, mgr et.SessionManager) et.Dispatcher {
	d := &dynamicDispatcher{
		log:    l,
		reg:    r,
		mgr:    mgr,
		done:   make(chan struct{}),
		cchan:  make(chan *et.EventDataElement, 1000),
		cqueue: queue.NewQueue(),
		pools:  make(map[oam.AssetType]*pipelinePool),
		meta:   newMetaMap(),
	}

	go d.runEvents()
	go d.updateMetaMap()
	return d
}

func (d *dynamicDispatcher) Shutdown() {
	// Optional: add pool-level shutdown if you want explicit draining.
	select {
	case <-d.done:
		return
	default:
	}
	close(d.done)
}

func (d *dynamicDispatcher) runEvents() {
	scale := time.NewTicker(5 * time.Second)
	defer scale.Stop()

	for {
		select {
		case <-d.done:
			return
		default:
		}

		select {
		case <-scale.C:
			for _, pool := range d.pools {
				if stats, err := d.snapshotSessBacklogStats(pool.eventTy); err == nil {
					_ = pool.maybeScale(stats)
					pool.maybeAdjustFanout(stats)
				}
			}
		case e := <-d.cchan:
			d.cqueue.Append(e)
		case <-d.cqueue.Signal():
			if data, ok := d.cqueue.Next(); ok {
				if ede, valid := data.(*et.EventDataElement); valid {
					d.completedCallback(ede)
				}
			}
		}
	}
}

func (d *dynamicDispatcher) completedCallback(ede *et.EventDataElement) {
	// ack the completion in the backlog
	if err := ede.Event.Session.Backlog().Ack(ede.Event.Entity, false); err == nil {
		_ = d.meta.DeleteSessionEntry(ede.Event.Session.ID().String(), ede.Event.Entity.ID)
	}

	if inst, ok := ede.Ref.(*pipelineInstance); ok {
		inst.onDequeue()
	}

	if err := ede.Error; err != nil {
		ede.Event.Session.Log().WithGroup("event").With("name", ede.Event.Name).Error(err.Error())
	}
}

func (d *dynamicDispatcher) DispatchEvent(e *et.Event) error {
	if e == nil || e.Entity == nil || e.Session == nil {
		return errors.New("the event cannot be nil and must include the entity and session")
	}

	// do not schedule the same asset more than once
	if e.Session.Backlog().Has(e.Entity) {
		return nil
	}

	if err := d.meta.InsertEntry(e.Session.ID().String(), e.Entity.ID, e.Meta); err != nil {
		return err
	}

	err := e.Session.Backlog().Enqueue(e.Entity)
	if err != nil {
		return err
	}

	atype := e.Entity.Asset.AssetType()
	pool := d.getOrCreatePool(atype)
	if pool == nil {
		return fmt.Errorf("no pipeline pool available for asset type %s", string(atype))
	}

	return pool.Dispatch(e)
}

func (d *dynamicDispatcher) ResubmitEvent(e *et.Event) error {
	if e == nil || e.Entity == nil || e.Session == nil {
		return errors.New("the event cannot be nil and must include the entity and session")
	}

	if !e.Session.Backlog().Has(e.Entity) {
		return errors.New("the event must already be in the backlog")
	}

	if err := d.meta.InsertEntry(e.Session.ID().String(), e.Entity.ID, e.Meta); err != nil {
		return err
	}

	err := e.Session.Backlog().Enqueue(e.Entity)
	if err != nil {
		return err
	}

	atype := e.Entity.Asset.AssetType()
	pool := d.getOrCreatePool(atype)
	if pool == nil {
		return fmt.Errorf("no pipeline pool available for asset type %s", string(atype))
	}

	return pool.Dispatch(e)
}

func (d *dynamicDispatcher) getOrCreatePool(atype oam.AssetType) *pipelinePool {
	d.RLock()
	pool := d.pools[atype]
	d.RUnlock()
	if pool != nil {
		return pool
	}

	d.Lock()
	defer d.Unlock()
	// check if the pool was created while waiting
	if pool = d.pools[atype]; pool != nil {
		return pool
	}

	min, max := assetTypeToPoolMinMax(atype)
	pool = newPipelinePool(d, atype, min, max)
	d.pools[atype] = pool
	return pool
}

func assetTypeToPoolMinMax(atype oam.AssetType) (int, int) {
	switch atype {
	case oam.FQDN:
		return 4, 32
	case oam.IPAddress:
		return 4, 32
	default:
		return 1, 4
	}
}

type sessStatsMap map[string]sessBacklogStats

type sessBacklogStats struct {
	Session   et.Session
	Queued    int64
	Leased    int64
	Processed int64
}

// snapshotSessBacklogStats returns a point-in-time map of sessions and
// their current stats from the backlog.
func (d *dynamicDispatcher) snapshotSessBacklogStats(atype oam.AssetType) (sessStatsMap, error) {
	sessions := d.mgr.GetSessions()

	stats := make(sessStatsMap, len(sessions))
	for _, sess := range sessions {
		if queued, leased, done, err := sess.Backlog().Counts(atype); err == nil {
			stats[sess.ID().String()] = sessBacklogStats{
				Session:   sess,
				Queued:    queued,
				Leased:    leased,
				Processed: done,
			}
		}
	}

	if len(stats) == 0 {
		return nil, errors.New("failed to acquire the stats")
	}
	return stats, nil
}

func (d *dynamicDispatcher) updateMetaMap() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-tick.C:
			d.removeKilledSessions()
		}
	}
}

func (d *dynamicDispatcher) removeKilledSessions() {
	sessions := d.mgr.GetSessions()
	if len(sessions) == 0 {
		return
	}

	var sids []string
	for _, sess := range sessions {
		sids = append(sids, sess.ID().String())
	}

	d.meta.RemoveInactiveSessions(sids)
}
