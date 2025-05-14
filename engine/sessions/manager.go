// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v4/config"
	et "github.com/owasp-amass/amass/v4/engine/types"
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
	if err == nil {
		err = r.AddSession(s)

		if err == nil {
			return s, nil
		}
	}
	return nil, err
}

// Add: adds a session to a session storage after checking the session config.
func (r *manager) AddSession(s et.Session) error {
	if s == nil {
		return errors.New("the provided session is nil")
	}

	r.Lock()
	if sess, ok := s.(*Session); ok {
		r.sessions[sess.id] = sess
	}
	r.Unlock()

	// TODO: Need to add the session config checks here (using the Registry)
	return nil
}

// CancelSession: cancels a session in a session storage.
func (r *manager) CancelSession(id uuid.UUID) {
	s := r.GetSession(id)
	if s == nil {
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
	defer r.Unlock()

	if qdb := r.sessions[id].Queue(); qdb != nil {
		if err := qdb.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the queue for session %s: %v", id, err))
		}
	}
	if c := r.sessions[id].Cache(); c != nil {
		_ = c.Close()
	}
	if s, ok := r.sessions[id].(*Session); ok {
		s.ranger = nil
	}
	if dir := r.sessions[id].TmpDir(); dir != "" {
		_ = os.RemoveAll(dir)
	}
	if db := s.DB(); db != nil {
		if err := db.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the database for session %s: %v", id, err))
		}
	}
	delete(r.sessions, id)
}

func (r *manager) GetSessions() []et.Session {
	r.RLock()
	defer r.RUnlock()

	sessions := make([]et.Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}

	return sessions
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
