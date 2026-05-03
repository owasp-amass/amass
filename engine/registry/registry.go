// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"fmt"
	"log/slog"
	"sync"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type registry struct {
	sync.RWMutex
	log      *slog.Logger
	handlers map[oam.AssetType]map[int][]*et.Handler
}

// Create a new instance of Registry.
func NewRegistry(l *slog.Logger) et.Registry {
	return &registry{
		log:      l,
		handlers: make(map[oam.AssetType]map[int][]*et.Handler),
	}
}

func (r *registry) Log() *slog.Logger {
	return r.log
}

// Register a Plugin Handler on the registry.
func (r *registry) RegisterHandler(h *et.Handler) error {
	r.Lock()
	defer r.Unlock()

	// is the entry for the requested event type currently empty?
	if _, found := r.handlers[h.EventType]; !found {
		r.handlers[h.EventType] = make(map[int][]*et.Handler)
	}
	// has this registration been made already?
	var found bool
loop:
	for _, handlers := range r.handlers[h.EventType] {
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

	if h.Position <= 0 {
		h.Position = 1
	} else if h.Position > 50 {
		h.Position = 50
	}

	atype, p := h.EventType, h.Position
	if handlers, found := r.handlers[atype][p]; found && len(handlers) > 0 && h.Exclusive {
		err := fmt.Errorf("handler at position %d already registered for EventType %s", p, atype)
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", h.Plugin.Name(), "handler", h.Name))
		return err
	}

	r.handlers[atype][p] = append(r.handlers[atype][p], h)
	return nil
}
