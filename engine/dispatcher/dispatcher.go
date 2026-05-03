// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/caffix/queue"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type limits struct {
	MaxQueued    int
	HighWater    int
	LowWater     int
	PerSessBurst int
}

type dispatcher struct {
	sync.RWMutex
	log      *slog.Logger
	reg      et.Registry
	mgr      et.SessionManager
	done     chan struct{}
	wake     chan oam.AssetType
	cqueue   queue.Queue
	cchan    chan *et.EventDataElement
	meta     *metaMap
	shuffler *rand.Rand
}

func NewDispatcher(l *slog.Logger, r et.Registry, mgr et.SessionManager) et.Dispatcher {
	// Create a new random source
	shuffler := rand.New(rand.NewSource(time.Now().UnixNano()))

	d := &dispatcher{
		log:      l,
		reg:      r,
		mgr:      mgr,
		done:     make(chan struct{}),
		wake:     make(chan oam.AssetType, 1),
		cchan:    make(chan *et.EventDataElement, 1000),
		cqueue:   queue.NewQueue(),
		meta:     newMetaMap(),
		shuffler: shuffler,
	}

	go d.runPump()
	go d.updateMetaMap()
	go d.processCompletedEvents()
	return d
}

func (d *dispatcher) Shutdown() {
	// Optional: add pool-level shutdown if you want explicit draining.
	select {
	case <-d.done:
		return
	default:
	}
	close(d.done)
}

func (d *dispatcher) DispatchEvent(e *et.Event) error {
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
		_ = d.meta.DeleteSessionEntry(e.Session.ID().String(), e.Entity.ID)
		return err
	}

	return d.signalScheduling(e)
}

func (d *dispatcher) signalScheduling(e *et.Event) error {
	atype := e.Entity.Asset.AssetType()
	pipe := e.Session.Pipelines()[atype]

	if pipe.Queue.Len() <= int(limitsByAssetType(atype).LowWater) {
		d.wakePump(atype)
	}

	return nil
}

func (d *dispatcher) ResubmitEvent(e *et.Event) error {
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
		_ = d.meta.DeleteSessionEntry(e.Session.ID().String(), e.Entity.ID)
		return err
	}

	return d.signalScheduling(e)
}

func (d *dispatcher) processCompletedEvents() {
	for {
		select {
		case <-d.done:
			return
		default:
		}

		select {
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

func (d *dispatcher) completedCallback(ede *et.EventDataElement) {
	// ack the completion in the backlog
	if err := ede.Event.Session.Backlog().Ack(ede.Event.Entity, false); err == nil {
		_ = d.meta.DeleteSessionEntry(ede.Event.Session.ID().String(), ede.Event.Entity.ID)
	}

	atype := ede.Event.Entity.Asset.AssetType()
	if ap, ok := ede.Ref.(*et.AssetPipeline); ok {
		if ap.Queue.Len() <= int(limitsByAssetType(atype).LowWater) {
			d.wakePump(atype)
		}
	}

	if err := ede.Error; err != nil {
		ede.Event.Session.Log().WithGroup("event").With("name", ede.Event.Name).Error(err.Error())
	}
}

func (d *dispatcher) wakePump(atype oam.AssetType) {
	select {
	case d.wake <- atype:
	default:
	}
}

func (d *dispatcher) runPump() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-d.done:
			return
		case atype := <-d.wake:
			d.pumpOnce(atype)
		case <-tick.C:
			for _, atype := range oam.AssetList {
				d.pumpOnce(atype)
			}
		}
	}
}

func (d *dispatcher) pumpOnce(atype oam.AssetType) {
	limits := limitsByAssetType(atype)
	if limits == nil {
		return
	}

	stats, err := d.snapshotSessBacklogStats(atype)
	if err != nil {
		return
	}

	// build a list of the session IDs
	sessions := make([]string, 0, len(stats))
	for sid := range stats {
		sessions = append(sessions, sid)
	}

	// shuffle the sessions for random selection
	d.shuffler.Shuffle(len(sessions), func(i, j int) {
		sessions[i], sessions[j] = sessions[j], sessions[i]
	})

	for _, sess := range sessions {
		s := stats[sess]
		if s.Queued == 0 {
			// there are zero entities to claim from the backlog
			continue
		}

		pipe := s.Session.Pipelines()[atype]
		numOfClaims := int(limits.MaxQueued) - pipe.Queue.Len()
		if numOfClaims <= 0 {
			continue
		}
		numOfClaims = min(numOfClaims, limits.PerSessBurst)

		entities, err := s.Session.Backlog().ClaimNext(atype, numOfClaims)
		if err != nil {
			continue
		}

		for _, ent := range entities {
			a := ent.Asset
			name := string(atype) + ": " + a.Key()
			meta, _ := d.meta.GetEntry(sess, ent.ID)

			event := &et.Event{
				Name:       name,
				Entity:     ent,
				Meta:       meta,
				Dispatcher: d,
				Session:    s.Session,
			}

			data := et.NewEventDataElement(event)
			data.Exit = d.cchan
			data.Ref = pipe // keep a ref to the pipeline
			if err := pipe.Queue.Append(data); err != nil {
				// entity is returned to the backlog in a queued state
				_ = s.Session.Backlog().Release(ent, atype, false)
			}
		}
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
func (d *dispatcher) snapshotSessBacklogStats(atype oam.AssetType) (sessStatsMap, error) {
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

func (d *dispatcher) updateMetaMap() {
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

func (d *dispatcher) removeKilledSessions() {
	var sids []string

	for _, sess := range d.mgr.GetSessions() {
		sids = append(sids, sess.ID().String())
	}

	d.meta.RemoveInactiveSessions(sids)
}

func limitsByAssetType(atype oam.AssetType) *limits {
	switch atype {
	case oam.FQDN:
		fallthrough
	case oam.IPAddress:
		return &limits{
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
		return &limits{
			MaxQueued:    100,
			HighWater:    75,
			LowWater:     25,
			PerSessBurst: 5,
		}
	}

	return &limits{
		MaxQueued:    20,
		HighWater:    15,
		LowWater:     5,
		PerSessBurst: 1,
	}
}
