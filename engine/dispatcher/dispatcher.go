// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const (
	MinPipelineQueueSize = 100
	MaxPipelineQueueSize = 500
)

type dis struct {
	logger *slog.Logger
	reg    et.Registry
	mgr    et.SessionManager
	done   chan struct{}
	dchan  chan *et.Event
	cchan  chan *et.EventDataElement
}

func NewDispatcher(l *slog.Logger, r et.Registry, mgr et.SessionManager) et.Dispatcher {
	if l == nil {
		l = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	d := &dis{
		logger: l,
		reg:    r,
		mgr:    mgr,
		done:   make(chan struct{}),
		dchan:  make(chan *et.Event, MinPipelineQueueSize),
		cchan:  make(chan *et.EventDataElement, MinPipelineQueueSize),
	}

	go d.maintainPipelines()
	return d
}

func (d *dis) Shutdown() {
	select {
	case <-d.done:
		return
	default:
	}
	close(d.done)
}

func (d *dis) DispatchEvent(e *et.Event) error {
	if e == nil {
		return errors.New("the event is nil")
	} else if e.Session == nil {
		return errors.New("the event has no associated session")
	} else if e.Session.Done() {
		return errors.New("the associated session has been terminated")
	} else if e.Entity == nil || e.Entity.Asset == nil {
		return errors.New("the event has no associated entity or asset")
	}

	d.dchan <- e
	return nil
}

func (d *dis) maintainPipelines() {
	ctick := time.NewTimer(time.Second)
	defer ctick.Stop()
	mtick := time.NewTimer(10 * time.Second)
	defer mtick.Stop()
loop:
	for {
		select {
		case <-d.done:
			break loop
		case <-mtick.C:
			checkOnTheHeap()
			mtick.Reset(10 * time.Second)
		default:
		}

		select {
		case <-ctick.C:
			d.fillPipelineQueues()
			ctick.Reset(time.Second)
		case e := <-d.dchan:
			if err := d.safeDispatch(e); err != nil {
				d.logger.Error(fmt.Sprintf("Failed to dispatch event: %s", err.Error()))
			}
		case e := <-d.cchan:
			d.completedCallback(e)
		}
	}
}

func checkOnTheHeap() {
	var mstats runtime.MemStats
	runtime.ReadMemStats(&mstats)

	h := mstats.HeapAlloc
	n := mstats.NextGC
	if h <= n {
		return
	}

	if diff := mstats.HeapAlloc - mstats.NextGC; bToMb(diff) > 500 {
		runtime.GC()
	}
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func (d *dis) fillPipelineQueues() {
	sessions := d.mgr.GetSessions()
	if len(sessions) == 0 {
		return
	}

	var ptypes []oam.AssetType
	for _, atype := range oam.AssetList {
		if ap, err := d.reg.GetPipeline(atype); err == nil {
			if ap.Queue.Len() < MinPipelineQueueSize {
				ptypes = append(ptypes, atype)
			}
		}
	}

	numRequested := MaxPipelineQueueSize / len(sessions)
	for _, s := range sessions {
		if s == nil || s.Done() {
			continue
		}
		for _, atype := range ptypes {
			if entities, err := s.Queue().Next(atype, numRequested); err == nil && len(entities) > 0 {
				for _, entity := range entities {
					e := &et.Event{
						Name:    fmt.Sprintf("%s - %s", string(atype), entity.Asset.Key()),
						Entity:  entity,
						Session: s,
					}
					if err := d.appendToPipeline(e); err != nil {
						d.logger.Error(fmt.Sprintf("Failed to append to a data pipeline: %s", err.Error()))
					}
				}
			}
		}
	}
}

func (d *dis) completedCallback(data interface{}) {
	ede, ok := data.(*et.EventDataElement)
	if !ok {
		return
	}

	if err := ede.Error; err != nil {
		ede.Event.Session.Log().WithGroup("event").With("name", ede.Event.Name).Error(err.Error())
	}
	// increment the number of events processed in the session
	if stats := ede.Event.Session.Stats(); stats != nil {
		stats.Lock()
		stats.WorkItemsCompleted++
		stats.Unlock()
	}
}

func (d *dis) safeDispatch(e *et.Event) error {
	// there is no need to dispatch the event if there's no associated asset pipeline
	if ap, err := d.reg.GetPipeline(e.Entity.Asset.AssetType()); err != nil || ap == nil {
		return err
	}

	// do not schedule the same asset more than once
	if e.Session.Queue().Has(e.Entity) {
		return nil
	}

	err := e.Session.Queue().Append(e.Entity)
	if err != nil {
		return err
	}

	// increment the number of events processed in the session
	if stats := e.Session.Stats(); stats != nil {
		stats.Lock()
		stats.WorkItemsTotal++
		stats.Unlock()
	}

	if e.Meta != nil {
		if err := d.appendToPipeline(e); err != nil {
			d.logger.Error(fmt.Sprintf("Failed to append to a data pipeline: %s", err.Error()))
			return err
		}
	}
	return nil
}

func (d *dis) appendToPipeline(e *et.Event) error {
	if e == nil || e.Session == nil || e.Entity == nil || e.Entity.Asset == nil {
		return errors.New("the event is nil")
	}

	ap, err := d.reg.GetPipeline(e.Entity.Asset.AssetType())
	if err != nil {
		return err
	}

	e.Dispatcher = d
	if data := et.NewEventDataElement(e); data != nil {
		_ = e.Session.Queue().Processed(e.Entity)
		data.Queue = d.cchan
		ap.Queue.Append(data)
	}
	return nil
}
