// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
)

func jobConfigFor(domain, apikey string) *config.Config {
	cfg := config.NewConfig()
	cfg.Scope = &config.Scope{Domains: []string{domain}}
	cfg.Resolvers = []string{"192.0.2.53"}
	cfg.GraphDBs = []*config.Database{{Primary: true, System: "postgres", Password: "db-secret"}}
	cfg.DataSrcConfigs = &config.DataSourceConfig{Datasources: []*config.DataSource{
		{Name: "Shodan", TTL: 1440, Creds: map[string]*config.Credentials{"a": {Apikey: apikey}}}}}
	return cfg
}

// jobSession is a session on repo with cfg, as far as jobs need one.
func jobSession(t *testing.T, repo repository.Repository, cfg *config.Config) *Session {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{id: uuid.New(), ctx: ctx, cancel: cancel, cfg: cfg, db: repo, start: time.Now(),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), stats: new(et.SessionStats), done: make(chan struct{})}
	s.runs, _ = repo.(repository.RunRecorder)
	s.scope = scope.CreateFromConfigScope(s)
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	})
	return s
}

// leave takes the session out of its job as Kill does: its renewal stops
// first.
func leave(s *Session) {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.leaveJob()
}

// start sets the session up as CreateSession does.
func start(t *testing.T, s *Session, want string) {
	t.Helper()
	if err := s.setupJob(want); err != nil {
		t.Fatal(err)
	}
	s.startRun()
	s.startJob()
}

// The job record keeps no database settings or credentials; a joining
// worker takes the job's configuration with its own.
func TestJobConfigLeavesOutWhatEachWorkerBrings(t *testing.T) {
	withDSN := jobConfigFor("example.com", "job-key")
	withDSN.Options = map[string]any{"database": "postgres://amass:dsn-secret@db:5432/assetdb", "resolvers_qps": 5}
	raw, err := jobConfig(withDSN)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(raw); strings.Contains(s, "db-secret") || strings.Contains(s, "job-key") ||
		strings.Contains(s, "dsn-secret") || !strings.Contains(s, "resolvers_qps") ||
		!strings.Contains(s, "example.com") {
		t.Fatalf("the job's configuration: %s", s)
	}

	local := jobConfigFor("other.org", "local-key")
	local.Resolvers = []string{"198.51.100.53"}
	cfg, err := mergeJobConfig(local, jobRecord{Config: raw})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scope.Domains[0] != "example.com" || cfg.Resolvers[0] != "198.51.100.53" ||
		cfg.GraphDBs[0].Password != "db-secret" {
		t.Errorf("merged: domains %v, resolvers %v", cfg.Scope.Domains, cfg.Resolvers)
	}
	if ds := cfg.GetDataSourceConfig("Shodan"); ds == nil || ds.TTL != 1440 || ds.Creds["a"].Apikey != "local-key" {
		t.Errorf("the merged data source: %+v", ds)
	}
	if scopeFingerprint(cfg) != scopeFingerprint(jobConfigFor("EXAMPLE.com", "")) ||
		scopeFingerprint(cfg) == scopeFingerprint(local) {
		t.Error("fingerprints do not tell scopes apart")
	}
}

// A second session of the same scope joins the running job, under its run;
// the last worker to leave ends the job; a job whose workers all stopped is
// ended by the next session that looks, and its queue deleted.
func TestSessionsJoinAndEndJobs(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	first := jobSession(t, repo, jobConfigFor("example.com", "k1"))
	start(t, first, "")
	if first.joined || first.job != first.id.String() || first.run == "" {
		t.Fatalf("the first session: job %s, joined %v, run %q", first.job, first.joined, first.run)
	}

	opted := jobConfigFor("example.com", "k2")
	opted.SetJoinRunningJobs(false)
	alone := jobSession(t, repo, opted)
	if err := alone.setupJob(""); err != nil || alone.joined {
		t.Errorf("a session told not to join joined: %v", err)
	}

	second := jobSession(t, repo, jobConfigFor("example.com", "k2"))
	start(t, second, "")
	if !second.joined || second.job != first.job || second.run != first.run {
		t.Fatalf("the second session: job %s, joined %v, run %q", second.job, second.joined, second.run)
	}
	if ds := second.cfg.GetDataSourceConfig("Shodan"); ds == nil || ds.Creds["a"].Apikey != "k2" {
		t.Errorf("the joining worker lost its own credentials: %+v", ds)
	}
	other := jobSession(t, repo, jobConfigFor("other.org", "k3"))
	if err := other.setupJob(first.job + "-gone"); err == nil {
		t.Error("joined a job that is not running")
	}
	// a worker that joins and fails before it starts leaves the job's run alone
	failed := jobSession(t, repo, jobConfigFor("example.com", "k4"))
	if err := failed.setupJob(""); err != nil || !failed.joined {
		t.Fatalf("the session did not join: %v", err)
	}
	leave(failed)
	if run, err := first.runs.FindRunById(context.Background(), first.run); err != nil || run.Status != dbt.RunRunning {
		t.Errorf("a worker that failed to start ended the job's run: %+v, %v", run, err)
	}
	// the worker is recorded before the job, so the job is never seen without one
	if recs, err := first.work.Read(0); err != nil || len(recs) < 2 || recs[0].Kind != JobWorkerKind ||
		recs[1].Kind != JobKind {
		t.Errorf("the first records are not the worker and then the job: %v", err)
	}

	// the first worker leaves the second behind
	leave(first)
	if jobEnded(t, first) {
		t.Fatal("the job ended while a worker remained")
	}
	leave(second)
	if !jobEnded(t, first) {
		t.Fatal("the last worker did not end the job")
	}
	ctx := context.Background()
	if run, err := first.runs.FindRunById(ctx, first.run); err != nil || run.Status != dbt.RunStopped {
		t.Errorf("the job's run: %+v, %v", run, err)
	}

	// a job whose worker stopped without leaving is ended by the next session
	crashed := jobSession(t, repo, jobConfigFor("crash.example", "k4"))
	start(t, crashed, "")
	q := repo.(repository.WorkQueue)
	if err := q.EnqueueWork(ctx, crashed.job, "FQDN", "1"); err != nil {
		t.Fatal(err)
	}
	crashed.leases.Release(workerLease(crashed.job, crashed.id.String()))
	next := jobSession(t, repo, jobConfigFor("crash.example", "k5"))
	start(t, next, "")
	if next.joined || !jobEnded(t, crashed) {
		t.Fatalf("the abandoned job was joined (%v) or not ended", next.joined)
	}
	if c, err := q.CountWorkByKind(ctx, crashed.job); err != nil || c.Total() != (dbt.WorkCounts{}) {
		t.Errorf("the abandoned job's queue: %+v, %v", c, err)
	}
}

// jobEnded reports whether the work topic records the end of s's job.
func jobEnded(t *testing.T, s *Session) bool {
	t.Helper()
	recs, err := s.work.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	jobs := map[string]*job{}
	foldJobs(jobs, recs)
	return jobs[s.job] != nil && jobs[s.job].Ended
}

// A worker counts the background work the job's other workers report.
func TestWorkersSeeEachOthersBackgroundWork(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	a := jobSession(t, repo, jobConfigFor("example.com", "k1"))
	start(t, a, "")
	b := jobSession(t, repo, jobConfigFor("example.com", "k2"))
	start(t, b, "")
	b.stats.AddBackground(2)
	b.renewWorker()

	recs, err := a.work.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	a.applyJobRecords(recs)
	if n := a.othersBackground(); n != 2 {
		t.Errorf("a sees %d units of background work, want b's 2", n)
	}
	var d workerData
	if l, ok := a.leases.Find(workerLease(b.job, b.id.String())); !ok || json.Unmarshal(l.Data, &d) != nil {
		t.Error("b's worker lease is missing")
	}

	// the job's workers, with the items each holds and did
	ctx, q, owner := context.Background(), repo.(repository.WorkQueue), b.id.String()+":FQDN"
	if err := q.EnqueueWork(ctx, a.job, "FQDN", "1", "2"); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ClaimWork(ctx, a.job, "FQDN", owner, 2, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := q.AckWork(ctx, a.job, "1", ""); err != nil {
		t.Fatal(err)
	}
	ws := a.Workers()
	if len(ws) != 2 {
		t.Fatalf("workers = %+v", ws)
	}
	for _, w := range ws {
		if !w.Live {
			t.Errorf("%s is not live", w.Worker)
		}
		if w.Worker == b.id.String() && (w.Leased != 1 || w.Done != 1 || w.Background != 2) {
			t.Errorf("b = %+v; want 1 leased, 1 done and 2 units of background work", w)
		}
	}
}

// A worker joining a job sizes its HTTP clients for the job's ports, not the
// ones its own configuration named.
func TestJoiningSizesClientsForTheJobsPorts(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	jobCfg := jobConfigFor("example.com", "k1")
	jobCfg.Scope.Ports = []int{80, 443, 8443}
	start(t, jobSession(t, repo, jobCfg), "")

	joiner := jobSession(t, repo, jobConfigFor("example.com", "k2"))
	c, err := NewClients(len(joiner.cfg.Scope.Ports), amassnet.LocalAddrs{}, amassnet.Route{})
	if err != nil {
		t.Fatal(err)
	}
	joiner.clients = c
	if err := joiner.setupJob(""); err != nil || !joiner.joined {
		t.Fatalf("the session did not join: %v", err)
	}
	if joiner.clients == c || joiner.clients.probTr.MaxIdleConnsPerHost != 3 {
		t.Errorf("the probe client allows %d connections per host, want 3 for the job's ports",
			joiner.clients.probTr.MaxIdleConnsPerHost)
	}
}
