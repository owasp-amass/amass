// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/caffix/queue"
	et "github.com/owasp-amass/amass/v4/engine/types"
)

type dis struct {
	logger    *slog.Logger
	reg       et.Registry
	mgr       et.SessionManager
	done      chan struct{}
	completed queue.Queue
}

func NewDispatcher(l *slog.Logger, r et.Registry, mgr et.SessionManager) et.Dispatcher {
	if l == nil {
		l = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	d := &dis{
		logger:    l,
		reg:       r,
		mgr:       mgr,
		done:      make(chan struct{}),
		completed: queue.NewQueue(),
	}

	go d.collectEvents()
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

func (d *dis) collectEvents() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-d.done:
			break loop
		case <-d.completed.Signal():
			if element, ok := d.completed.Next(); ok {
				d.completedCallback(element)
			}
		case <-t.C:
			if element, ok := d.completed.Next(); ok {
				d.completedCallback(element)
			}
		}
	}
	d.completed.Process(d.completedCallback)
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
	stats := ede.Event.Session.Stats()
	stats.Lock()
	stats.WorkItemsCompleted++
	stats.Unlock()
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

	ap, err := d.reg.GetPipeline(e.Entity.Asset.AssetType())
	if err != nil {
		return err
	}

	e.Dispatcher = d
	// do not schedule the same asset more than once
	set := e.Session.EventSet()
	if set.Has(e.Entity.ID) {
		return errors.New("this event was processed previously")
	}
	set.Insert(e.Entity.ID)

	if data := et.NewEventDataElement(e); data != nil {
		data.Queue = d.completed
		ap.Queue.Append(data)
		// increment the number of events processed in the session
		stats := e.Session.Stats()
		stats.Lock()
		stats.WorkItemsTotal++
		stats.Unlock()
	}
	return nil
}
