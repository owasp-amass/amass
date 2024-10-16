// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"fmt"
	"log/slog"
	"sync"

	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type registry struct {
	sync.RWMutex
	logger    *slog.Logger
	handlers  map[string]map[int][]*et.Handler
	pipelines map[string]*et.AssetPipeline
}

// Create a new instance of Registry
func NewRegistry(l *slog.Logger) et.Registry {
	return &registry{
		logger:    l,
		handlers:  make(map[string]map[int][]*et.Handler),
		pipelines: make(map[string]*et.AssetPipeline),
	}
}

func (r *registry) Log() *slog.Logger {
	return r.logger
}

// Register a Plugin Handler on the registry:
func (r *registry) RegisterHandler(h *et.Handler) error {
	r.Lock()
	defer r.Unlock()

	// is the entry currently empty?
	if _, found := r.handlers[string(h.EventType)]; !found {
		r.handlers[string(h.EventType)] = make(map[int][]*et.Handler)
	}
	// has this registration been made already?
	var found bool
loop:
	for _, handlers := range r.handlers[string(h.EventType)] {
		for _, handler := range handlers {
			if handler.Name == h.Name {
				found = true
				break loop
			}
		}
	}
	if found {
		err := fmt.Errorf("handler %s already registered for EventType %s", h.Name, h.EventType)
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", h.Plugin.Name(), "handler", h.Name))
		return err
	}

	if h.Priority == 0 {
		h.Priority = 5
	} else if h.Priority < 0 {
		h.Priority = 1
	} else if h.Priority > 9 {
		h.Priority = 9
	}

	et, p := string(h.EventType), h.Priority
	r.handlers[et][p] = append(r.handlers[et][p], h)
	return nil
}

func (r *registry) GetPipeline(eventType oam.AssetType) (*et.AssetPipeline, error) {
	r.RLock()
	defer r.RUnlock()

	if p, found := r.pipelines[string(eventType)]; found {
		return p, nil
	}
	return nil, fmt.Errorf("no handlers registered for the EventType: %s", eventType)
}
