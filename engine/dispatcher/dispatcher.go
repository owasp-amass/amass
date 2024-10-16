// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"log/slog"
	"os"

	"github.com/caffix/queue"
	et "github.com/owasp-amass/engine/types"
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
loop:
	for {
		select {
		case <-d.done:
			break loop
		case <-d.completed.Signal():
			d.completed.Process(d.completedCallback)
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
	} else if e.Session.Done() {
		return errors.New("the session has been terminated")
	}

	e.Dispatcher = d
	a := e.Asset.Asset
	// do not schedule the same asset more than once
	if p, hit := e.Session.Cache().GetAsset(a); p != nil && hit {
		return errors.New("this event was processed previously")
	}
	e.Session.Cache().SetAsset(e.Asset)

	ap, err := d.reg.GetPipeline(a.AssetType())
	if err != nil {
		return err
	}

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
