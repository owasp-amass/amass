// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"fmt"
	"sync/atomic"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

var ErrBackpressure = errors.New("backpressure")

type pipelineInstance struct {
	parent   *pipelinePool
	id       string
	atype    oam.AssetType
	ap       *et.AssetPipeline
	draining atomic.Bool
	queued   atomic.Int64
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

	id := p.nextInstanceID()
	inst := &pipelineInstance{
		parent: p,
		id:     id,
		atype:  p.eventTy,
		ap:     ap,
	}
	p.instances[id] = inst
	p.ring.Add(id)

	p.log.Info("created pipeline instance", "atype", p.eventTy, "id", id)
	return inst
}

// nextInstanceID allocates a unique ID independent of map length.
func (p *pipelinePool) nextInstanceID() string {
	var id string

	for {
		p.nextInstanceSeq++
		id = fmt.Sprintf("%s-%d", p.eventTy, p.nextInstanceSeq)
		if _, exists := p.instances[id]; !exists {
			break
		}
		p.log.Error("pipeline instance id collision", "atype", p.eventTy, "id", id)
	}

	return id
}

func (pi *pipelineInstance) canAccept() bool {
	if pi.draining.Load() {
		return false
	}
	return pi.queueLen() < pi.parent.limits.MaxQueued
}

func (pi *pipelineInstance) enqueue(e *et.Event) error {
	if !pi.canAccept() {
		return ErrBackpressure
	}

	// Only increment AFTER admission decision
	_ = pi.queued.Add(1)

	e.Dispatcher = pi.parent.dis
	data := et.NewEventDataElement(e)
	data.Exit = pi.parent.dis.cchan
	data.Ref = pi // keep a ref to the instance
	return pi.ap.Queue.Append(data)
}

func (pi *pipelineInstance) onDequeue() {
	qlen := pi.queued.Add(-1)

	if pi.draining.Load() {
		if qlen == 0 {
			pi.parent.Lock()
			defer pi.parent.Unlock()

			delete(pi.parent.instances, pi.id)
			pi.parent.log.Info("removed idle pipeline instance",
				"atype", pi.parent.eventTy,
				"id", pi.id,
			)
		}
		return
	}

	// Wake the pool pump when we are below lowWater
	if pi.queueLen() <= pi.parent.limits.LowWater {
		pi.parent.notifyCapacity()
	}
}

func (pi *pipelineInstance) queueLen() int64 {
	return int64(pi.ap.Queue.Len())
}
