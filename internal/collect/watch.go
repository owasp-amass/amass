// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// Watch re-runs one approved plan on a schedule, so changes to a target's
// attack surface are collected without asking each time. Approving a watch
// approves every run of its exact plan until the watch is removed.
type Watch struct {
	ID         string        `json:"id"`
	Plan       Plan          `json:"plan"`
	Interval   time.Duration `json:"interval"`
	ApprovedBy string        `json:"approved_by"`
	CreatedAt  time.Time     `json:"created_at"`
	NextRunAt  time.Time     `json:"next_run_at"`
	LastRunID  string        `json:"last_run_id,omitempty"`
	LastRunAt  time.Time     `json:"last_run_at,omitzero"`
	LastError  string        `json:"last_error,omitempty"`
	// Changes is what the last finished run found, as the Summarize hook
	// described it.
	Changes   string    `json:"changes,omitempty"`
	ChangesAt time.Time `json:"changes_at,omitzero"`
	Removed   bool      `json:"removed,omitempty"`
}

// Watch limits.
const (
	MinWatchInterval  = 6 * time.Hour
	MaxWatches        = 32
	watchCheckEvery   = time.Minute
	watchRetryOnError = time.Hour
)

// Watches schedules watches on a Manager. Watches are kept in Path (JSON)
// when it is set, so they survive a restart.
type Watches struct {
	Manager *Manager
	Path    string
	// Summarize describes what a finished run found; nil records nothing.
	Summarize func(ctx context.Context, run Run) string
	Now       func() time.Time

	mu      sync.Mutex
	watches map[string]*Watch
	loaded  bool
}

func (w *Watches) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}

	return time.Now()
}

func (w *Watches) load() {
	if w.loaded {
		return
	}

	w.loaded = true
	w.watches = map[string]*Watch{}
	if w.Path == "" {
		return
	}

	data, err := os.ReadFile(w.Path)
	if err != nil {
		return
	}

	var list []*Watch
	if json.Unmarshal(data, &list) == nil {
		for _, x := range list {
			if x != nil && x.ID != "" && !x.Removed {
				w.watches[x.ID] = x
			}
		}
	}
}

// save writes the watches. The caller holds w.mu.
func (w *Watches) save() error {
	if w.Path == "" {
		return nil
	}

	list := make([]*Watch, 0, len(w.watches))
	for _, x := range w.watches {
		list = append(list, x)
	}

	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	tmp := w.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, w.Path)
}

// Add creates a watch of an approved plan whose first run starts now.
func (w *Watches) Add(plan Plan, interval time.Duration, approvedBy string) (Watch, error) {
	if !plan.Approvable() {
		return Watch{}, errors.New("not an approvable collection plan: " + plan.Reason)
	}
	if interval < MinWatchInterval {
		return Watch{}, fmt.Errorf("a watch runs at most every %s", MinWatchInterval)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.load()
	for _, x := range w.watches {
		if x.Plan.ID == plan.ID {
			return *x, fmt.Errorf("watch %s already covers this scope", x.ID)
		}
	}
	if len(w.watches) >= MaxWatches {
		return Watch{}, fmt.Errorf("%d watches is the limit; remove one first", MaxWatches)
	}

	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return Watch{}, err
	}

	now := w.now()
	x := &Watch{ID: "watch-" + hex.EncodeToString(b), Plan: plan, Interval: interval, ApprovedBy: approvedBy,
		CreatedAt: now, NextRunAt: now}
	w.watches[x.ID] = x
	return *x, w.save()
}

// Remove stops a watch; a run it started keeps going until it ends.
func (w *Watches) Remove(id string) (Watch, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.load()
	x, ok := w.watches[id]
	if !ok {
		return Watch{}, fmt.Errorf("no watch %s", id)
	}

	delete(w.watches, id)
	x.Removed = true
	return *x, w.save()
}

// List returns the watches, the earliest created first.
func (w *Watches) List() []Watch {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.load()
	out := make([]Watch, 0, len(w.watches))
	for _, x := range w.watches {
		out = append(out, *x)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Tick starts the runs that are due and records what finished runs found.
// Run calls it every minute; tests call it directly.
func (w *Watches) Tick(ctx context.Context) {
	w.mu.Lock()
	w.load()
	var due, finished []*Watch
	now := w.now()
	for _, x := range w.watches {
		if x.LastRunID != "" && x.ChangesAt.Before(x.LastRunAt) {
			if r, ok := w.Manager.Get(x.LastRunID); ok && r.Finished() {
				finished = append(finished, x)
			}
		}
		if !now.Before(x.NextRunAt) {
			due = append(due, x)
		}
	}

	w.mu.Unlock()

	for _, x := range finished {
		run, _ := w.Manager.Get(x.LastRunID)
		summary := fmt.Sprintf("Run %s %s", run.ID, run.State)
		if w.Summarize != nil && (run.State == StateFinished || run.State == StateTimedOut) {
			summary = w.Summarize(ctx, run)
		}

		w.mu.Lock()
		if cur, ok := w.watches[x.ID]; ok {
			cur.Changes, cur.ChangesAt = summary, w.now()
			_ = w.save()
		}

		w.mu.Unlock()
	}

	for _, x := range due {
		run, err := w.Manager.Start(ctx, x.Plan, fmt.Sprintf("%s, approved by %s", x.ID, x.ApprovedBy))
		w.mu.Lock()
		cur, ok := w.watches[x.ID]
		if !ok {
			w.mu.Unlock()
			continue
		}
		if err != nil {
			// Busy (the running limit, or this scope already running):
			// try again later without skipping the interval.
			cur.LastError, cur.NextRunAt = err.Error(), w.now().Add(watchRetryOnError)
		} else {
			cur.LastError = ""
			cur.LastRunID, cur.LastRunAt = run.ID, run.StartedAt
			cur.NextRunAt = run.StartedAt.Add(cur.Interval)
		}

		_ = w.save()
		w.mu.Unlock()
	}
}

// Run checks the watches every minute until ctx ends.
func (w *Watches) Run(ctx context.Context) {
	t := time.NewTicker(watchCheckEvery)
	defer t.Stop()
	w.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}
