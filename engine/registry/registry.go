// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"fmt"
	"log/slog"
	"sync"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

type registry struct {
	sync.RWMutex
	log      *slog.Logger
	handlers map[string]map[int][]*et.Handler
}

// Create a new instance of Registry.
func NewRegistry(l *slog.Logger) et.Registry {
	return &registry{
		log:      l,
		handlers: make(map[string]map[int][]*et.Handler),
	}
}

func (r *registry) Log() *slog.Logger {
	return r.log
}

// Register a Plugin Handler on the registry.
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

	if h.Position <= 0 {
		h.Position = 1
	} else if h.Position > 50 {
		h.Position = 50
	}

	et, p := string(h.EventType), h.Position
	r.handlers[et][p] = append(r.handlers[et][p], h)
	return nil
}
