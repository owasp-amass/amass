// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph"
	oam "github.com/owasp-amass/open-asset-model"
)

func TestPlansBindScopeAndMode(t *testing.T) {
	sel := graph.AssetSelector{Type: "FQDN", Field: "name", Value: "Example.ORG."}
	p, a := NewPlan(sel, Passive), NewPlan(sel, Active)
	if p.Status != StatusApprovalRequired || a.Status != StatusApprovalRequired || p.ScopeValue != "example.org" {
		t.Fatalf("plans = %+v %+v", p, a)
	}
	if p.ID == a.ID || p.ID != PlanID("domain", "example.org", Passive) {
		t.Errorf("passive and active must have different IDs: %s %s", p.ID, a.ID)
	}
	if len(a.Methods) < 2 || a.Effects == "" {
		t.Errorf("active plan must say what it does: %+v", a)
	}
	if bad := NewPlan(sel, "loud"); bad.Status != StatusUnsupported {
		t.Errorf("unknown mode planned: %+v", bad)
	}

	wide := graph.AssetSelector{Type: "Netblock", Field: "cidr", Value: "8.0.0.0/8"}
	if NewPlan(wide, Active).Status != StatusUnsupported || NewPlan(wide, Passive).Status != StatusApprovalRequired {
		t.Error("active collection of a /8 must be refused, passive allowed")
	}
	for _, s := range []graph.AssetSelector{
		{Type: "IPAddress", Field: "address", Value: "10.0.0.1"},
		{Type: "Organization", Field: "name", Value: "Acme"},
		{Type: "FQDN", Field: "name", Value: "bad..example.org"},
	} {
		if NewPlan(s, Passive).Status != StatusUnsupported {
			t.Errorf("unsafe plan for %+v", s)
		}
	}
}

func TestConfigureNarrowsScope(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Scope.Ports = []int{22, 443, 8443}
	cfg.ProvidedNames = []string{"other.example"}
	plan := NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "example.org"}, Active)
	if _, err := Configure(cfg, plan); err != nil {
		t.Fatal(err)
	}
	if !cfg.Active || !cfg.BruteForcing || cfg.Passive || !cfg.Rigid || len(cfg.ProvidedNames) != 0 ||
		len(cfg.Scope.Domains) != 1 || len(cfg.Scope.Ports) != 3 {
		t.Errorf("active config = %+v scope %+v", cfg, cfg.Scope)
	}

	cfg = config.NewConfig()
	cfg.Scope.Ports = []int{22}
	plan = NewPlan(graph.AssetSelector{Type: "Netblock", Field: "cidr", Value: "8.8.8.0/24"}, Passive)
	asset, err := Configure(cfg, plan)
	if err != nil || asset == nil || cfg.Active || !cfg.Passive || len(cfg.Scope.CIDRs) != 1 ||
		len(cfg.Scope.Ports) != len(config.DefaultPorts) {
		t.Errorf("passive config = %+v, %v", cfg.Scope, err)
	}

	tampered := plan
	tampered.ScopeValue = "1.1.1.0/24"
	if _, err := Configure(config.NewConfig(), tampered); err == nil {
		t.Error("a plan whose scope does not match its ID was configured")
	}
}

type fakeEngine struct {
	mu         sync.Mutex
	sessions   map[uuid.UUID]*et.SessionStats
	seeded     []oam.Asset
	terminated []uuid.UUID
	seedErr    error
}

func newFake() *fakeEngine { return &fakeEngine{sessions: map[uuid.UUID]*et.SessionStats{}} }

func (f *fakeEngine) CreateSession(context.Context, *config.Config) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.New()
	f.sessions[id] = &et.SessionStats{}
	return id, nil
}

func (f *fakeEngine) CreateAsset(_ context.Context, _ uuid.UUID, a oam.Asset) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seedErr != nil {
		return "", f.seedErr
	}

	f.seeded = append(f.seeded, a)
	return "1", nil
}

func (f *fakeEngine) SessionStats(_ context.Context, id uuid.UUID) (*et.SessionStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return nil, errors.New("no session")
	}

	return &et.SessionStats{WorkItemsCompleted: s.WorkItemsCompleted, WorkItemsTotal: s.WorkItemsTotal}, nil
}

func (f *fakeEngine) TerminateSession(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, id)
	f.terminated = append(f.terminated, id)
	return nil
}

func (f *fakeEngine) ListSessions(context.Context) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []uuid.UUID
	for id := range f.sessions {
		out = append(out, id)
	}

	return out, nil
}

func (f *fakeEngine) progress(id string, done, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[uuid.MustParse(id)]
	s.WorkItemsCompleted, s.WorkItemsTotal = done, total
}

func waitState(t *testing.T, m *Manager, id, state string) Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r, _ := m.Get(id); r.State == state {
			return r
		}

		time.Sleep(5 * time.Millisecond)
	}

	r, _ := m.Get(id)
	t.Fatalf("run %s is %s, want %s", id, r.State, state)
	return r
}

func newManager(f *fakeEngine, journal string) *Manager {
	return &Manager{Engine: f, Config: func() (*config.Config, error) { return config.NewConfig(), nil },
		Journal: journal, PollInterval: time.Millisecond, IdleTimeout: time.Hour}
}

func TestManagerRunsFinishAndStop(t *testing.T) {
	f := newFake()
	journal := filepath.Join(t.TempDir(), "runs.jsonl")
	m := newManager(f, journal)
	defer m.Close()
	ctx := context.Background()

	a := NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "a.example"}, Passive)
	run, err := m.Start(ctx, a, "tester")
	if err != nil || run.State != StateRunning || len(f.seeded) != 1 {
		t.Fatalf("start = %+v, %v", run, err)
	}
	if _, err := m.Start(ctx, a, "tester"); err == nil {
		t.Error("the same scope was started twice")
	}

	f.progress(run.ID, 10, 10)
	done := waitState(t, m, run.ID, StateFinished)
	if done.Completed != 10 || done.EndedAt.IsZero() {
		t.Errorf("finished run = %+v", done)
	}

	b := NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "b.example"}, Active)
	run, err = m.Start(ctx, b, "tester")
	if err != nil {
		t.Fatal(err)
	}

	f.progress(run.ID, 1, 50)
	if stopped, err := m.Stop(ctx, run.ID); err != nil || stopped.State != StateStopped {
		t.Errorf("stop = %+v, %v", stopped, err)
	}
	if len(f.terminated) != 2 {
		t.Errorf("terminated = %v", f.terminated)
	}

	// A new manager reads the journal.
	again := newManager(f, journal)
	defer again.Close()
	if runs := again.Runs(); len(runs) != 2 || runs[0].State != StateStopped || runs[1].State != StateFinished {
		t.Errorf("journal runs = %+v", runs)
	}
}

func TestManagerLimitsTimeoutsAndResume(t *testing.T) {
	f := newFake()
	journal := filepath.Join(t.TempDir(), "runs.jsonl")
	m := newManager(f, journal)
	m.MaxRunning = 1
	m.IdleTimeout = 20 * time.Millisecond
	ctx := context.Background()

	run, err := m.Start(ctx, NewPlan(graph.AssetSelector{Type: "AutonomousSystem", Field: "number", Value: "64500"},
		Passive), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(ctx, NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "c.example"},
		Passive), ""); err == nil {
		t.Error("the running limit was not enforced")
	}

	waitState(t, m, run.ID, StateTimedOut)
	m.Close()

	// A run recorded as running is resumed when the engine still has it and
	// marked lost when it does not.
	f2 := newFake()
	m2 := newManager(f2, journal)
	live, _ := m2.Start(ctx, NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "d.example"}, Passive), "")
	m2.Close()
	f2.mu.Lock()
	delete(f2.sessions, uuid.MustParse(live.ID))
	f2.mu.Unlock()
	m3 := newManager(f2, journal)
	defer m3.Close()
	if err := m3.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := m3.Get(live.ID); r.State != StateLost {
		t.Errorf("a vanished session = %+v", r)
	}

	f2.seedErr = errors.New("boom")
	m4 := newManager(f2, "")
	defer m4.Close()
	if _, err := m4.Start(ctx, NewPlan(graph.AssetSelector{Type: "FQDN", Field: "name", Value: "e.example"},
		Passive), ""); err == nil || len(f2.sessions) != 0 {
		t.Errorf("a failed seed left a session: %v %v", err, f2.sessions)
	}
}
