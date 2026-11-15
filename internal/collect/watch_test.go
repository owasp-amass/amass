// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

func TestWatchesScheduleRuns(t *testing.T) {
	f := newFake()
	m := newManager(f, "")
	defer m.Close()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "watches.json")
	w := &Watches{Manager: m, Path: path, Now: func() time.Time { return now },
		Summarize: func(_ context.Context, r Run) string { return "found things for " + r.Plan.ScopeValue }}
	ctx := context.Background()

	plan := NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "watch.example"}, Passive)
	if _, err := w.Add(plan, time.Hour, "tester"); err == nil {
		t.Error("a watch more often than the minimum was accepted")
	}

	x, err := w.Add(plan, 24*time.Hour, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Add(plan, 24*time.Hour, "tester"); err == nil {
		t.Error("a second watch of the same scope was accepted")
	}

	w.Tick(ctx)
	got := w.List()[0]
	if got.LastRunID == "" || !got.NextRunAt.Equal(now.Add(24*time.Hour)) || len(f.seeded) != 1 {
		t.Fatalf("after the first tick: %+v", got)
	}

	run, _ := m.Get(got.LastRunID)
	if run.ApprovedBy != x.ID+", approved by tester" {
		t.Errorf("approved by = %q", run.ApprovedBy)
	}

	// Nothing is due before the interval; a finished run's changes are
	// recorded on the next tick.
	f.progress(got.LastRunID, 5, 5)
	waitState(t, m, got.LastRunID, StateFinished)
	now = now.Add(time.Hour)
	w.Tick(ctx)
	got = w.List()[0]
	if len(f.seeded) != 1 || got.Changes != "found things for watch.example" {
		t.Errorf("after an hour: %+v (seeded %d)", got, len(f.seeded))
	}

	now = now.Add(24 * time.Hour)
	w.Tick(ctx)
	if len(f.seeded) != 2 {
		t.Errorf("the watch did not run again after its interval")
	}

	// Watches survive a restart and can be removed.
	again := &Watches{Manager: m, Path: path, Now: func() time.Time { return now }}
	if list := again.List(); len(list) != 1 || list[0].ID != x.ID {
		t.Fatalf("reloaded = %+v", list)
	}
	if _, err := again.Remove(x.ID); err != nil || len(again.List()) != 0 {
		t.Errorf("remove: %v", err)
	}
	if third := (&Watches{Manager: m, Path: path}); len(third.List()) != 0 {
		t.Error("a removed watch came back")
	}
}
