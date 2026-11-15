// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

func runSession(t *testing.T) (*Session, repository.RunRecorder) {
	t.Helper()

	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "runs.db"))
	if err != nil {
		t.Fatalf("the database was not opened: %v", err)
	}

	t.Cleanup(func() { _ = repo.Close() })

	runs, ok := repo.(repository.RunRecorder)
	if !ok {
		t.Fatal("the SQLite repository does not record collection runs")
	}

	_, cidr, _ := net.ParseCIDR("192.0.2.0/24")
	cfg := config.NewConfig()
	cfg.Active = true
	cfg.Scope = &config.Scope{Domains: []string{"Example.COM"}, Addresses: []net.IP{net.ParseIP("198.51.100.7")},
		CIDRs: []*net.IPNet{cidr}, ASNs: []int{64496}}

	s := &Session{id: uuid.New(), start: time.Now().UTC().Truncate(time.Millisecond), cfg: cfg,
		stats: new(et.SessionStats), runs: runs}
	return s, runs
}

func TestSessionRecordsItsRun(t *testing.T) {
	s, runs := runSession(t)
	s.startRun()
	if s.run == "" {
		t.Fatal("the session did not start a run")
	}

	run, err := runs.FindRunById(context.Background(), s.run)
	if err != nil {
		t.Fatalf("the run was not stored: %v", err)
	}
	if run.Tool != "amass" || run.ExternalID != s.id.String() || run.Status != dbt.RunRunning {
		t.Errorf("the run was recorded as %+v", run)
	}

	want := []dbt.RunTarget{{Type: oam.FQDN, Key: "example.com"}, {Type: oam.IPAddress, Key: "198.51.100.7"},
		{Type: oam.Netblock, Key: "192.0.2.0/24"}, {Type: oam.AutonomousSystem, Key: "64496"}}
	if len(run.Scope) != len(want) {
		t.Fatalf("the run's scope is %v, expected %v", run.Scope, want)
	}
	for i := range want {
		if run.Scope[i] != want[i] {
			t.Errorf("scope entry %d is %v, expected %v", i, run.Scope[i], want[i])
		}
	}
	if run.Metadata["mode"] != "active" {
		t.Errorf("the run's mode is %v", run.Metadata["mode"])
	}

	s.stats.WorkItemsTotal, s.stats.WorkItemsCompleted = 10, 10
	s.finishRun()
	run, err = runs.FindRunById(context.Background(), s.run)
	if err != nil || run.Status != dbt.RunFinished || run.FinishedAt.IsZero() {
		t.Errorf("a session with all work done should finish its run: %+v, %v", run, err)
	}
}

func TestSessionWithWorkLeftStopsItsRun(t *testing.T) {
	for name, set := range map[string]func(*et.SessionStats){
		"queued":     func(ss *et.SessionStats) { ss.WorkItemsTotal, ss.WorkItemsCompleted = 10, 4 },
		"background": func(ss *et.SessionStats) { ss.WorkItemsTotal, ss.WorkItemsCompleted = 3, 3; ss.AddBackground(1) },
		"nothing":    func(*et.SessionStats) {},
	} {
		t.Run(name, func(t *testing.T) {
			s, runs := runSession(t)
			s.startRun()
			set(s.stats)
			s.finishRun()

			run, err := runs.FindRunById(context.Background(), s.run)
			if err != nil || run.Status != dbt.RunStopped {
				t.Errorf("the run should be stopped: %+v, %v", run, err)
			}
		})
	}
}

func TestSessionWithoutRunRecorderSkipsRuns(t *testing.T) {
	s := &Session{id: uuid.New(), cfg: config.NewConfig(), stats: new(et.SessionStats)}
	s.startRun()
	s.finishRun()
	if s.run != "" {
		t.Errorf("a session without a recorder has run %q", s.run)
	}
}
