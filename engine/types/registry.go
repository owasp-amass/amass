// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"errors"
	"log/slog"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	oam "github.com/owasp-amass/open-asset-model"
)

type Plugin interface {
	Name() string
	Start(r Registry) error
	Stop()
}

type Handler struct {
	Plugin       Plugin
	Name         string
	Position     int
	Exclusive    bool
	MaxInstances int
	EventType    oam.AssetType
	Transforms   []string
	Callback     func(*Event) error
}

type AssetPipeline struct {
	Pipeline *pipeline.Pipeline
	Queue    *PipelineQueue
}

type Registry interface {
	Log() *slog.Logger
	RegisterHandler(h *Handler) error
	BuildAssetPipeline(ctx context.Context, atype oam.AssetType) (*AssetPipeline, error)
}

type PipelineQueue struct {
	draining bool
	drainCh  chan struct{}
	q        queue.Queue
}

func NewPipelineQueue() *PipelineQueue {
	return &PipelineQueue{
		q:       queue.NewQueue(),
		drainCh: make(chan struct{}, 1),
	}
}

func (pq *PipelineQueue) Len() int {
	return pq.q.Len()
}

func (pq *PipelineQueue) Append(data *EventDataElement) error {
	if pq.draining {
		return errors.New("pipeline queue is draining")
	}
	pq.q.Append(data)
	return nil
}

func (pq *PipelineQueue) Drain() {
	if pq.draining {
		return
	}
	pq.draining = true
	close(pq.drainCh)
}

// Next implements the pipeline InputSource interface.
func (pq *PipelineQueue) Next(ctx context.Context) bool {
	if pq.q.Len() > 0 {
		return true
	}

	for {
		select {
		case <-pq.drainCh:
			if pq.q.Len() == 0 {
				return false
			}
			return true
		case <-ctx.Done():
			return false
		case <-pq.q.Signal():
			if pq.q.Len() > 0 {
				return true
			}
		}
	}
}

// Data implements the pipeline InputSource interface.
func (pq *PipelineQueue) Data() pipeline.Data {
	for {
		element, good := pq.q.Next()
		if !good {
			break
		}

		if ede, ok := element.(*EventDataElement); ok && !ede.Event.Session.Done() {
			return ede
		}
	}
	return nil
}

// Error implements the pipeline InputSource interface.
func (pq *PipelineQueue) Error() error {
	return nil
}
