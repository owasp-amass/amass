// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

/*
 * Amass Engine allow users to create multiple sessions.
 * Each session has its own configuration.
 * The session manager is responsible for managing all sessions,
 * it's a singleton object and it's thread-safe.
 */

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/config/config"
	et "github.com/owasp-amass/engine/types"
)

type manager struct {
	sync.RWMutex
	logger   *slog.Logger
	sessions map[uuid.UUID]et.Session
}

// NewManager: creates a new session storage.
func NewManager(l *slog.Logger) et.SessionManager {
	return &manager{
		logger:   l,
		sessions: make(map[uuid.UUID]et.Session),
	}
}

func (r *manager) NewSession(cfg *config.Config) (et.Session, error) {
	s, err := CreateSession(cfg)
	if err != nil {
		return nil, err
	}
	if _, err = r.AddSession(s); err != nil {
		return nil, err
	}
	return s, nil
}

// Add: adds a session to a session storage after checking the session config.
func (r *manager) AddSession(s et.Session) (uuid.UUID, error) {
	if s == nil {
		return uuid.UUID{}, nil
	}

	r.Lock()
	defer r.Unlock()

	var id uuid.UUID
	if sess, ok := s.(*Session); ok {
		id = sess.id
		r.sessions[id] = sess
	}
	// TODO: Need to add the session config checks here (using the Registry)
	return id, nil
}

// CancelSession: cancels a session in a session storage.
func (r *manager) CancelSession(id uuid.UUID) {
	r.Lock()
	s, found := r.sessions[id]
	r.Unlock()

	if !found {
		return
	}
	s.Kill()

	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for range t.C {
		ss := s.Stats()
		ss.Lock()
		total := ss.WorkItemsTotal
		completed := ss.WorkItemsCompleted
		ss.Unlock()
		if completed >= total {
			break
		}
	}

	r.Lock()
	if c := r.sessions[id].Cache(); c != nil {
		c.Close()
	}
	if db := s.DB(); db != nil {
		if err := db.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the database for session %s: %v", id, err))
		}
	}
	delete(r.sessions, id)
	r.Unlock()
}

// GetSession: returns a session from a session storage.
func (r *manager) GetSession(id uuid.UUID) et.Session {
	r.RLock()
	defer r.RUnlock()

	if s, found := r.sessions[id]; found {
		return s
	}
	return nil
}

// Shutdown: cleans all sessions from a session storage and shutdown the session storage.
func (r *manager) Shutdown() {
	var list []uuid.UUID

	r.Lock()
	for k := range r.sessions {
		list = append(list, k)
	}
	r.Unlock()

	var wg sync.WaitGroup
	for _, id := range list {
		wg.Add(1)
		go func(id uuid.UUID, wg *sync.WaitGroup) {
			defer wg.Done()

			r.CancelSession(id)
		}(id, &wg)
	}
	wg.Wait()
}
