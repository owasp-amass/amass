// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Engine is the part of the engine API client a Manager uses.
type Engine interface {
	CreateSession(ctx context.Context, cfg *config.Config) (uuid.UUID, error)
	CreateAsset(ctx context.Context, token uuid.UUID, asset oam.Asset) (string, error)
	SessionStats(ctx context.Context, token uuid.UUID) (*et.SessionStats, error)
	TerminateSession(ctx context.Context, token uuid.UUID) error
	ListSessions(ctx context.Context) ([]uuid.UUID, error)
}

// Run states.
const (
	StateRunning  = "running"
	StateFinished = "finished"
	StateStopped  = "stopped"
	StateTimedOut = "timed_out"
	StateFailed   = "failed"
	StateLost     = "lost"
)

// Run is one supervised enumeration session.
type Run struct {
	ID             string    `json:"id"`
	Plan           Plan      `json:"plan"`
	State          string    `json:"state"`
	StartedAt      time.Time `json:"started_at"`
	EndedAt        time.Time `json:"ended_at,omitzero"`
	LastProgressAt time.Time `json:"last_progress_at,omitzero"`
	Completed      int       `json:"work_items_completed"`
	Total          int       `json:"work_items_total"`
	ApprovedBy     string    `json:"approved_by,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// Finished reports whether the run has ended.
func (r Run) Finished() bool { return r.State != StateRunning }

// Defaults bound what one approval can cost.
const (
	DefaultIdleTimeout  = 30 * time.Minute
	DefaultMaxDuration  = 24 * time.Hour
	DefaultPollInterval = 5 * time.Second
	DefaultMaxRunning   = 2
	// settledPolls is how many polls in a row must find every work item
	// done before a run counts as finished, as amass enum does.
	settledPolls = 5
	// maxPollErrors ends a run whose engine stops answering.
	maxPollErrors = 12
)

// Manager starts enumeration sessions for approved plans and supervises them
// until they finish, stall, exceed their time or are stopped, then ends the
// engine session. Runs are recorded in Journal (JSON lines) when it is set,
// so a restarted manager lists earlier runs and resumes supervising those
// the engine still has.
type Manager struct {
	Engine Engine
	// Config returns a freshly loaded configuration for each session.
	Config       func() (*config.Config, error)
	Journal      string
	IdleTimeout  time.Duration
	MaxDuration  time.Duration
	PollInterval time.Duration
	MaxRunning   int
	Now          func() time.Time

	mu      sync.Mutex
	runs    map[string]*Run
	cancels map[string]context.CancelFunc
	loaded  bool
	wg      sync.WaitGroup
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}

	return time.Now()
}

func orDefault[T int | time.Duration](v, d T) T {
	if v > 0 {
		return v
	}

	return d
}

// load reads the journal once. The caller holds m.mu.
func (m *Manager) load() {
	if m.loaded {
		return
	}

	m.loaded = true
	m.runs = map[string]*Run{}
	m.cancels = map[string]context.CancelFunc{}
	if m.Journal == "" {
		return
	}

	f, err := os.Open(m.Journal)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	lines := bufio.NewScanner(f)
	lines.Buffer(make([]byte, 64<<10), 1<<20)
	for lines.Scan() {
		var r Run
		if json.Unmarshal(lines.Bytes(), &r) == nil && r.ID != "" {
			m.runs[r.ID] = &r
		}
	}
}

// record appends a run's state to the journal. The caller holds m.mu.
func (m *Manager) record(r *Run) {
	if m.Journal == "" {
		return
	}

	data, err := json.Marshal(r)
	if err != nil {
		return
	}

	f, err := os.OpenFile(m.Journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}

	_, _ = f.Write(append(data, '\n'))
	_ = f.Close()
}

// Resume supervises again the runs the journal records as running and the
// engine still has; the others are marked lost. Call it once at startup.
func (m *Manager) Resume(ctx context.Context) error {
	m.mu.Lock()
	m.load()
	var pending []*Run
	for _, r := range m.runs {
		if r.State == StateRunning {
			pending = append(pending, r)
		}
	}

	m.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}

	live, listErr := m.Engine.ListSessions(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range pending {
		token, err := uuid.Parse(r.ID)
		switch {
		case err != nil:
		case listErr != nil:
			// The engine cannot say which sessions it has (it may still be
			// starting): supervise the run anyway, so polling either picks it
			// back up or marks it failed, rather than leaving it recorded as
			// running with nothing watching it.
			m.supervise(token, r)
			continue
		case slices.Contains(live, token):
			m.supervise(token, r)
			continue
		}

		r.State, r.EndedAt = StateLost, m.now()
		r.Error = "the engine no longer has this session"
		m.record(r)
	}

	if listErr != nil {
		return fmt.Errorf("list engine sessions: %w", listErr)
	}
	return nil
}

// Start opens an engine session for an approved plan, seeds it with the
// plan's targets and supervises it. approvedBy names who approved it.
func (m *Manager) Start(ctx context.Context, plan Plan, approvedBy string) (Run, error) {
	if m.Engine == nil || m.Config == nil {
		return Run{}, errors.New("the enumeration engine is not configured")
	}

	m.mu.Lock()
	m.load()
	running := 0
	for _, r := range m.runs {
		if r.State == StateRunning {
			running++
			if r.Plan.ID == plan.ID {
				m.mu.Unlock()
				return *r, fmt.Errorf("run %s is already collecting this scope", r.ID)
			}
		}
	}

	m.mu.Unlock()
	if limit := orDefault(m.MaxRunning, DefaultMaxRunning); running >= limit {
		return Run{}, fmt.Errorf("%d enumerations are already running (the limit); stop one or wait", running)
	}

	cfg, err := m.Config()
	if err != nil {
		return Run{}, fmt.Errorf("load configuration: %w", err)
	}

	assets, err := configure(cfg, plan)
	if err != nil {
		return Run{}, err
	}

	token, err := m.Engine.CreateSession(ctx, cfg)
	if err != nil {
		return Run{}, fmt.Errorf("create the enumeration session: %w", err)
	}
	// A seed failure must not leave an idle, unsupervised session behind.
	for _, asset := range assets {
		if _, err := m.Engine.CreateAsset(ctx, token, asset); err != nil {
			_ = m.Engine.TerminateSession(context.Background(), token)
			return Run{}, fmt.Errorf("seed the enumeration session: %w", err)
		}
	}

	now := m.now()
	r := &Run{ID: token.String(), Plan: plan, State: StateRunning, StartedAt: now, LastProgressAt: now,
		ApprovedBy: approvedBy}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[r.ID] = r
	m.record(r)
	m.supervise(token, r)
	return *r, nil
}

// supervise polls a run until it ends. The caller holds m.mu.
func (m *Manager) supervise(token uuid.UUID, r *Run) {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancels[r.ID] = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.poll(ctx, token, r.ID)
	}()
}

func (m *Manager) poll(ctx context.Context, token uuid.UUID, id string) {
	tick := time.NewTicker(orDefault(m.PollInterval, DefaultPollInterval))
	defer tick.Stop()
	settled, errs := 0, 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		stats, err := m.Engine.SessionStats(sctx, token)
		cancel()
		if ctx.Err() != nil {
			return
		}

		m.mu.Lock()
		r := m.runs[id]
		if r == nil || r.State != StateRunning {
			m.mu.Unlock()
			return
		}

		now := m.now()
		end := ""
		switch {
		case err != nil || stats == nil:
			if errs++; errs >= maxPollErrors {
				end, r.Error = StateFailed, fmt.Sprintf("the engine stopped answering: %v", err)
			}
		default:
			errs = 0
			stats.RLock()
			completed, total := stats.WorkItemsCompleted, stats.WorkItemsTotal
			stats.RUnlock()
			if completed != r.Completed || total != r.Total {
				r.LastProgressAt = now
			}

			r.Completed, r.Total = completed, total
			if total > 0 && completed >= total {
				settled++
			} else {
				settled = 0
			}
			switch {
			case settled >= settledPolls:
				end = StateFinished
			case now.Sub(r.LastProgressAt) > orDefault(m.IdleTimeout, DefaultIdleTimeout):
				end, r.Error = StateTimedOut, "no progress within the idle timeout"
			case now.Sub(r.StartedAt) > orDefault(m.MaxDuration, DefaultMaxDuration):
				end, r.Error = StateTimedOut, "the run exceeded its maximum duration"
			}
		}
		if end == "" {
			m.mu.Unlock()
			continue
		}

		r.State, r.EndedAt = end, now
		delete(m.cancels, id)
		m.record(r)
		m.mu.Unlock()
		_ = m.Engine.TerminateSession(context.Background(), token)
		return
	}
}

// Stop ends a running run and its engine session.
func (m *Manager) Stop(ctx context.Context, id string) (Run, error) {
	m.mu.Lock()
	m.load()
	r, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return Run{}, fmt.Errorf("no enumeration run %s", id)
	}
	if r.State != StateRunning {
		out := *r
		m.mu.Unlock()
		return out, fmt.Errorf("run %s is already %s", id, r.State)
	}
	if cancel := m.cancels[id]; cancel != nil {
		cancel()
		delete(m.cancels, id)
	}

	r.State, r.EndedAt = StateStopped, m.now()
	m.record(r)
	out := *r
	m.mu.Unlock()

	token, err := uuid.Parse(id)
	if err != nil {
		return out, err
	}
	if err := m.Engine.TerminateSession(ctx, token); err != nil {
		return out, fmt.Errorf("the run was marked stopped but the engine did not end the session: %w", err)
	}

	return out, nil
}

// Get returns a run.
func (m *Manager) Get(id string) (Run, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	r, ok := m.runs[id]
	if !ok {
		return Run{}, false
	}

	return *r, true
}

// Runs lists the runs, the most recently started first.
func (m *Manager) Runs() []Run {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	out := make([]Run, 0, len(m.runs))
	for _, r := range m.runs {
		out = append(out, *r)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

// Close stops supervising without ending the engine sessions, which a
// restarted manager resumes. It waits for the pollers to return.
func (m *Manager) Close() {
	m.mu.Lock()
	for _, cancel := range m.cancels {
		cancel()
	}

	m.cancels = map[string]context.CancelFunc{}
	m.mu.Unlock()
	m.wg.Wait()
}
