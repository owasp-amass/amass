// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

type manager struct {
	sync.RWMutex
	logger   *slog.Logger
	registry et.Registry
	sessions map[uuid.UUID]et.Session
	// clients counts the clients of each session: a session working on a
	// job is given to each client that asks for the job's scope, and ends
	// when the last one cancels it.
	clients map[uuid.UUID]int
}

// NewManager: creates a new session storage.
func NewManager(l *slog.Logger, reg et.Registry) et.SessionManager {
	return &manager{
		logger:   l,
		registry: reg,
		sessions: make(map[uuid.UUID]et.Session),
		clients:  make(map[uuid.UUID]int),
	}
}

// NewSession creates a session for cfg, or, when one of the engine's
// sessions already works on the running job of cfg's scope on cfg's
// database, gives that one to this client too: one worker per engine.
func (r *manager) NewSession(cfg *config.Config) (et.Session, error) {
	if s := r.workingOn(cfg); s != nil {
		return joinedSession{s}, nil
	}

	s, err := CreateSession(r, r.registry, cfg)
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

	if s.Done() {
		return errors.New("the session ended before it could be added")
	}

	r.Lock()
	if sess, ok := s.(*Session); ok {
		r.sessions[sess.id] = sess
		r.clients[sess.id] = 1
	}
	r.Unlock()

	// TODO: Need to add the session config checks here (using the Registry)
	return nil
}

// CancelSession: cancels a client's session. A session other clients of its
// job still use goes on for them.
func (r *manager) CancelSession(id uuid.UUID) {
	r.Lock()
	if n := r.clients[id]; n > 1 {
		r.clients[id] = n - 1
		r.Unlock()
		return
	}
	r.Unlock()
	r.endSession(id)
}

// endSession ends a session for all of its clients. Of callers ending one
// session at once, the first to take it out of the manager ends it.
func (r *manager) endSession(id uuid.UUID) {
	r.Lock()
	s, ok := r.sessions[id]
	delete(r.sessions, id)
	delete(r.clients, id)
	r.Unlock()
	if !ok || s == nil {
		return
	}
	s.Kill()

	time.Sleep(10 * time.Second)
	if backlog := s.Backlog(); backlog != nil {
		if err := backlog.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the backlog for session %s: %v", id, err))
		}
	}
	if dir := s.TmpDir(); dir != "" {
		_ = os.RemoveAll(dir)
	}
	if db := s.DB(); db != nil {
		if err := db.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the database for session %s: %v", id, err))
		}
	}
	s.PubSub().Close()
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

func (r *manager) NumOfSessions() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.sessions)
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

			r.endSession(id)
		}(id, &wg)
	}
	wg.Wait()
}

// workingOn returns the engine's session working on the running job of
// cfg's scope on cfg's database, counting one more client of it, or nil
// when there is none or cfg asks not to join running jobs.
func (r *manager) workingOn(cfg *config.Config) *Session {
	if cfg == nil || !cfg.JoinsRunningJobs() {
		return nil
	}
	fp := scopeFingerprint(cfg)
	dsn, _, err := primaryDSN(cfg)
	if fp == "" || err != nil {
		return nil
	}

	r.Lock()
	defer r.Unlock()
	for id, es := range r.sessions {
		s, ok := es.(*Session)
		if !ok || s.work == nil || s.Done() || s.dsn != dsn || scopeFingerprint(s.cfg) != fp {
			continue
		}
		r.clients[id]++
		return s
	}
	return nil
}

// jobs are the jobs the engine's sessions work on, clients' and the pool's.
func (r *manager) jobs() map[string]bool {
	r.RLock()
	defer r.RUnlock()

	out := map[string]bool{}
	for _, es := range r.sessions {
		if s, ok := es.(*Session); ok && s.job != "" {
			out[s.job] = true
		}
	}
	return out
}

// joinedSession is a session given to another client of its job, which
// reports the job as joined.
type joinedSession struct{ *Session }

// Job returns the session's job, joined.
func (j joinedSession) Job() (string, bool) { return j.job, true }
