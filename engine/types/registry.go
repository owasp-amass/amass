// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"log/slog"
	"time"

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
	Priority     int
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
	BuildPipelines() error
	GetPipeline(eventType oam.AssetType) (*AssetPipeline, error)
}

type PipelineQueue struct {
	queue.Queue
}

func NewPipelineQueue() *PipelineQueue {
	return &PipelineQueue{queue.NewQueue()}
}

// Next implements the pipeline InputSource interface.
func (pq *PipelineQueue) Next(ctx context.Context) bool {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	if pq.Queue.Len() > 0 {
		return true
	}

	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			if pq.Queue.Len() > 0 {
				return true
			}
		case <-pq.Queue.Signal():
			if pq.Queue.Len() > 0 {
				return true
			}
		}
	}
}

// Data implements the pipeline InputSource interface.
func (pq *PipelineQueue) Data() pipeline.Data {
	for {
		element, good := pq.Queue.Next()
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
