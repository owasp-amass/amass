// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/coord"
	oam "github.com/owasp-amass/open-asset-model"
)

// Engine is the part of the engine API client a Manager uses.
type Engine interface {
	// NewSession creates a session, which may join a running job of the
	// same scope on the engines' database.
	NewSession(ctx context.Context, cfg *config.Config) (*client.CreateSessionResponse, error)
	CreateAsset(ctx context.Context, token uuid.UUID, asset oam.Asset) (string, error)
	SessionStats(ctx context.Context, token uuid.UUID) (*et.SessionStats, error)
	// SessionWorkers lists the engine sessions working on the session's job.
	SessionWorkers(ctx context.Context, token uuid.UUID) ([]et.WorkerStats, error)
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
	// Job is the job the run's session works on, shared with the other
	// engines on the database; Joined is set when the session joined a
	// running job of the same scope, under that job's configuration.
	Job    string `json:"job,omitempty"`
	Joined bool   `json:"joined,omitempty"`
	// Activity counts what the run's companions did, such as the documents
	// the document model read and the leads it submitted. It is replaced, not
	// changed in place, so a copy of the Run can be read without the lock.
	Activity map[string]int `json:"activity,omitempty"`
}

// Finished reports whether the run has ended.
func (r Run) Finished() bool { return r.State != StateRunning }

// Defaults bound what one approval can cost.
const (
	DefaultIdleTimeout  = 30 * time.Minute
	DefaultMaxDuration  = 24 * time.Hour
	DefaultPollInterval = 5 * time.Second
	// settledPolls is how many polls in a row must find every work item
	// done before a run counts as finished, as amass enum does.
	settledPolls = 5
	// maxPollErrors ends a run whose engine stops answering.
	maxPollErrors = 12
	// DefaultHoldLimit is the longest a run whose engine work is done is kept
	// open for a companion's pending work.
	DefaultHoldLimit = 15 * time.Minute
)

// Activity is what a Companion may do for a run: hand assets to the run's
// engine session, where the engine checks them like any other lead, and
// count what it did (Run.Activity).
type Activity struct {
	Submit func(ctx context.Context, asset oam.Asset) (string, error)
	Count  func(name string, n int)
	// Progress reports the run's work items completed and in total, a
	// measure of its size.
	Progress func() (completed, total int)
}

// Companion works beside a supervised run, such as the document model reading
// the documents the run collects. Begin starts the work, which must stop when
// ctx is done (the run ended), and returns whether work is still pending; while
// it is, a run whose engine work is done is kept open, up to the Manager's
// HoldLimit. Begin must return promptly and run its work in its own goroutine.
type Companion interface {
	Begin(ctx context.Context, run Run, act Activity) (pending func() bool)
}

// Finisher is a Companion with work to do when a run has ended (finished,
// stopped, timed out or lost), such as settling the leads it gave the run.
// It is not called when the manager closes with the run still going, since
// the run is resumed later.
type Finisher interface {
	Finish(ctx context.Context, run Run)
}

// finishTimeout bounds a companion's Finish.
const finishTimeout = 5 * time.Minute

// Manager starts enumeration sessions for approved plans and supervises them
// until they finish, stall, exceed their time or are stopped, then ends the
// engine session. Runs are recorded in the database's runs topic when RunTopic
// is set, otherwise in Journal (JSON lines) when that is set, so a restarted
// manager lists earlier runs and resumes supervising those the engine still
// has, and managers on one database see each other's runs.
type Manager struct {
	Engine Engine
	// Config returns a freshly loaded configuration for each session.
	Config   func() (*config.Config, error)
	Journal  string
	RunTopic *coord.Topic
	// Leases keeps managers on one database from supervising one run
	// twice; nil supervises every run.
	Leases       *coord.Leases
	IdleTimeout  time.Duration
	MaxDuration  time.Duration
	PollInterval time.Duration
	Now          func() time.Time
	// Companions work beside every supervised run; HoldLimit bounds how long
	// their pending work keeps a finished run open (0: 15 minutes; negative:
	// never).
	Companions []Companion
	HoldLimit  time.Duration

	mu      sync.Mutex
	runs    map[string]*Run
	cancels map[string]context.CancelFunc
	loaded  bool
	// runSeq is how far the runs topic has been read.
	runSeq int64
	wg     sync.WaitGroup
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
		// a run another manager on the database supervises is its own
		release, ok := m.Leases.Hold(context.Background(), runLease(r.ID), runLeaseTTL)
		if !ok {
			continue
		}

		token, err := uuid.Parse(r.ID)
		switch {
		case err != nil:
		case listErr != nil:
			// The engine cannot say which sessions it has (it may still be
			// starting): supervise the run anyway, so polling either picks it
			// back up or marks it failed, rather than leaving it recorded as
			// running with nothing watching it.
			m.supervise(token, r, release)
			continue
		case slices.Contains(live, token):
			m.supervise(token, r, release)
			continue
		}

		r.State, r.EndedAt = StateLost, m.now()
		r.Error = "the engine no longer has this session"
		m.record(r)
		release()
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
	for _, r := range m.runs {
		if r.State == StateRunning && r.Plan.ID == plan.ID {
			m.mu.Unlock()
			return *r, fmt.Errorf("run %s is already collecting this scope", r.ID)
		}
	}
	m.mu.Unlock()

	cfg, err := m.Config()
	if err != nil {
		return Run{}, fmt.Errorf("load configuration: %w", err)
	}

	assets, err := configure(cfg, plan)
	if err != nil {
		return Run{}, err
	}

	created, err := m.Engine.NewSession(ctx, cfg)
	if err != nil {
		return Run{}, fmt.Errorf("create the enumeration session: %w", err)
	}
	token, err := uuid.Parse(created.SessionToken)
	if err != nil {
		return Run{}, fmt.Errorf("create the enumeration session: %w", err)
	}
	// The engine gives a running job's session to each client that asks for
	// the job's scope; a run of this manager already holding it keeps it,
	// and this request's client count is given back.
	m.mu.Lock()
	m.load()
	if r, ok := m.runs[token.String()]; ok && r.State == StateRunning {
		m.mu.Unlock()
		_ = m.Engine.TerminateSession(context.Background(), token)
		return *r, fmt.Errorf("run %s is already collecting this scope", r.ID)
	}
	m.mu.Unlock()
	// A seed failure must not leave an idle, unsupervised session behind.
	for _, asset := range assets {
		if _, err := m.Engine.CreateAsset(ctx, token, asset); err != nil {
			_ = m.Engine.TerminateSession(context.Background(), token)
			return Run{}, fmt.Errorf("seed the enumeration session: %w", err)
		}
	}

	now := m.now()
	r := &Run{ID: token.String(), Plan: plan, State: StateRunning, StartedAt: now, LastProgressAt: now,
		ApprovedBy: approvedBy, Job: created.JobID, Joined: created.Joined}
	release, _ := m.Leases.Hold(context.Background(), runLease(r.ID), runLeaseTTL)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[r.ID] = r
	m.record(r)
	m.supervise(token, r, release)
	return *r, nil
}

// supervise polls a run until it ends. The caller holds m.mu.
func (m *Manager) supervise(token uuid.UUID, r *Run, release func()) {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancels[r.ID] = cancel
	m.wg.Add(1)
	id := r.ID
	go func() {
		defer m.wg.Done()
		defer release()
		defer cancel()
		pending := m.begin(ctx, token, id)
		m.poll(ctx, token, id, pending)
		m.finish(id)
	}()
}

// finish calls the companions that finish runs, once the run has ended.
func (m *Manager) finish(id string) {
	m.mu.Lock()
	r := m.runs[id]
	if r == nil || r.State == StateRunning {
		m.mu.Unlock()
		return
	}
	run := *r
	m.mu.Unlock()

	for _, c := range m.Companions {
		if f, ok := c.(Finisher); ok {
			ctx, cancel := context.WithTimeout(context.Background(), finishTimeout)
			f.Finish(ctx, run)
			cancel()
		}
	}
}

// begin starts the companions for a run and returns whether any has work
// pending, or nil when there are none.
func (m *Manager) begin(ctx context.Context, token uuid.UUID, id string) func() bool {
	if len(m.Companions) == 0 {
		return nil
	}

	m.mu.Lock()
	r := m.runs[id]
	var run Run
	if r != nil {
		run = *r
	}
	m.mu.Unlock()
	if r == nil {
		return nil
	}

	act := Activity{
		Submit: func(ctx context.Context, asset oam.Asset) (string, error) {
			return m.Engine.CreateAsset(ctx, token, asset)
		},
		Progress: func() (int, int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if r := m.runs[id]; r != nil {
				return r.Completed, r.Total
			}
			return 0, 0
		},
		Count: func(name string, n int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if r := m.runs[id]; r != nil {
				next := make(map[string]int, len(r.Activity)+1)
				for k, v := range r.Activity {
					next[k] = v
				}
				next[name] += n
				r.Activity = next
			}
		},
	}

	var pendings []func() bool
	for _, c := range m.Companions {
		if p := c.Begin(ctx, run, act); p != nil {
			pendings = append(pendings, p)
		}
	}
	return func() bool {
		for _, p := range pendings {
			if p() {
				return true
			}
		}
		return false
	}
}

func (m *Manager) poll(ctx context.Context, token uuid.UUID, id string, pending func() bool) {
	tick := time.NewTicker(orDefault(m.PollInterval, DefaultPollInterval))
	defer tick.Stop()
	settled, errs := 0, 0
	var holdFrom time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		stats, err := m.Engine.SessionStats(sctx, token)
		// A failed poll may be the engine starting or busy, which is worth
		// waiting out; but an engine that answers its session list without
		// this session has said for certain that the run is gone (it was
		// restarted), and waiting would only keep the run's scope blocked.
		gone := false
		if err != nil || stats == nil {
			if live, lerr := m.Engine.ListSessions(sctx); lerr == nil && !slices.Contains(live, token) {
				gone = true
			}
		}
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
		case gone:
			end, r.Error = StateLost, "the engine no longer has this session"
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
			case settled >= settledPolls && m.HoldLimit >= 0 && pending != nil && pending() &&
				(holdFrom.IsZero() || now.Sub(holdFrom) < orDefault(m.HoldLimit, DefaultHoldLimit)):
				// the engine is done, but a companion is still working (an
				// unread document may yet give a lead): keep the run open
				if holdFrom.IsZero() {
					holdFrom = now
				}
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

// Workers lists the engine sessions working on a running run's job, with
// the items each holds and did, or nil for a run that has ended.
func (m *Manager) Workers(ctx context.Context, id string) ([]et.WorkerStats, error) {
	r, ok := m.Get(id)
	if !ok {
		return nil, fmt.Errorf("no enumeration run %s", id)
	}
	if r.Finished() {
		return nil, nil
	}
	token, err := uuid.Parse(r.ID)
	if err != nil {
		return nil, err
	}
	return m.Engine.SessionWorkers(ctx, token)
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
// SubmitToRunning hands the asset to the engine session of every running
// enumeration, where the engine checks it like any other lead and its
// expansion policy decides what is investigated. It returns the runs that
// took it.
func (m *Manager) SubmitToRunning(ctx context.Context, asset oam.Asset) ([]string, error) {
	var took []string
	var errs []error
	for _, r := range m.Runs() {
		if r.Finished() {
			continue
		}
		token, err := uuid.Parse(r.ID)
		if err != nil {
			continue
		}
		if _, err := m.Engine.CreateAsset(ctx, token, asset); err != nil {
			errs = append(errs, fmt.Errorf("run %s: %w", r.ID, err))
			continue
		}
		took = append(took, r.ID)
	}
	return took, errors.Join(errs...)
}

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
