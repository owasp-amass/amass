// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Managers on one database record their runs in its runs topic and see each
// other's; a runs file is moved into an empty topic once.
func TestManagerRunsInTheDatabase(t *testing.T) {
	db := &coord.FakeStore{}
	ctx := context.Background()

	file := filepath.Join(t.TempDir(), "runs.jsonl")
	old := newManager(newFake(), file)
	run, err := old.Start(ctx, NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "old.example"},
		Passive), "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = old.Stop(ctx, run.ID)
	old.Close()

	a := newManager(newFake(), file)
	a.RunTopic = coord.Open(db, "runs")
	defer a.Close()
	if runs := a.Runs(); len(runs) != 1 || runs[0].ID != run.ID {
		t.Fatalf("the file's runs were not moved in: %+v", runs)
	}
	if _, err := os.Stat(file); err != nil {
		t.Error("the runs file was removed")
	}

	b := newManager(newFake(), "")
	b.RunTopic = coord.Open(db, "runs")
	defer b.Close()
	started, err := a.Start(ctx, NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "new.example"},
		Passive), "")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := b.Get(started.ID); !ok || got.Plan.ScopeValue != "new.example" {
		t.Errorf("another manager's run = %+v, %v", got, ok)
	}

	again := newManager(newFake(), file)
	again.RunTopic = coord.Open(db, "runs")
	defer again.Close()
	if runs := again.Runs(); len(runs) != 2 {
		t.Errorf("the file's runs were moved in twice: %+v", runs)
	}
}

// Servers on one database share their watches through its watches topic:
// one adds, another sees and removes it; a watches file is moved in once.
func TestWatchesInTheDatabase(t *testing.T) {
	db := &coord.FakeStore{}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	m := newManager(newFake(), "")
	defer m.Close()

	path := filepath.Join(t.TempDir(), "watches.json")
	file := &Watches{Manager: m, Path: path, Now: func() time.Time { return now }}
	old, err := file.Add(NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "old.example"}, Passive),
		24*time.Hour, "tester")
	if err != nil {
		t.Fatal(err)
	}

	a := &Watches{Manager: m, Path: path, Topic: coord.Open(db, "watches"), Now: func() time.Time { return now }}
	b := &Watches{Manager: m, Topic: coord.Open(db, "watches"), Now: func() time.Time { return now }}
	if list := a.List(); len(list) != 1 || list[0].ID != old.ID {
		t.Fatalf("the file's watches were not moved in: %+v", list)
	}

	x, err := a.Add(NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "new.example"}, Passive),
		24*time.Hour, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if list := b.List(); len(list) != 2 {
		t.Fatalf("another server's watches = %+v", list)
	}
	if _, err := b.Remove(x.ID); err != nil {
		t.Fatal(err)
	}
	if list := a.List(); len(list) != 1 || list[0].ID != old.ID {
		t.Errorf("a watch another server removed is still listed: %+v", list)
	}
}

// A run another manager on the database supervises is left to it: resuming
// neither supervises it again nor marks it lost; a watch's due run starts on
// one server.
func TestLeasesShareRunsAndWatches(t *testing.T) {
	db, leases := &coord.FakeStore{}, &coord.FakeLeases{}
	ctx := context.Background()
	open := func(holder string) *Manager {
		m := newManager(newFake(), "")
		m.RunTopic, m.Leases = coord.Open(db, "runs"), &coord.Leases{Store: leases, Holder: holder}
		return m
	}

	a := open("a")
	defer a.Close()
	run, err := a.Start(ctx, NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "a.example"}, Passive), "")
	if err != nil {
		t.Fatal(err)
	}
	if leases.Holder(runLease(run.ID)) != "a" {
		t.Fatal("the supervising manager does not hold the run's lease")
	}

	// b's engine has no such session; without the lease it would mark the
	// run lost
	b := open("b")
	defer b.Close()
	if err := b.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Get(run.ID); got.State != StateRunning {
		t.Errorf("another manager's run was marked %s", got.State)
	}

	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	wa := &Watches{Manager: open("wa"), Topic: coord.Open(db, "watches"),
		Leases: &coord.Leases{Store: leases, Holder: "wa"}, Now: func() time.Time { return now }}
	wb := &Watches{Manager: open("wb"), Topic: coord.Open(db, "watches"),
		Leases: &coord.Leases{Store: leases, Holder: "wb"}, Now: func() time.Time { return now }}
	defer wa.Manager.Close()
	defer wb.Manager.Close()
	if _, err := wa.Add(NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "w.example"}, Passive),
		24*time.Hour, "tester"); err != nil {
		t.Fatal(err)
	}
	wa.Tick(ctx)
	wb.Tick(ctx)
	fa, fb := wa.Manager.Engine.(*fakeEngine), wb.Manager.Engine.(*fakeEngine)
	if len(fa.seeded)+len(fb.seeded) != 1 {
		t.Errorf("the due run started %d times", len(fa.seeded)+len(fb.seeded))
	}
}
