// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/coord"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

// A second engine on a public address another engine holds is refused on
// that database; the address is free again once the other engine lets go.
func TestOneEnginePerPublicAddress(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	addr := netip.MustParseAddr("198.51.100.7")
	amassnet.SetEgress(addr)
	t.Cleanup(func() { amassnet.SetEgress(netip.Addr{}) })

	other := &coord.Leases{Store: repo.(coord.LeaseStore), Holder: "another-engine"}
	if !other.Try(egressLease(addr), time.Minute) {
		t.Fatal("the other engine did not take the address")
	}
	s := jobSession(t, repo, jobConfigFor("example.com", "k1"))
	if err := s.setupJob(""); err == nil || !strings.Contains(err.Error(), "198.51.100.7") {
		t.Fatalf("a second engine on the address was not refused: %v", err)
	}

	other.Release(egressLease(addr))
	s = jobSession(t, repo, jobConfigFor("example.com", "k1"))
	if err := s.setupJob(""); err != nil {
		t.Fatal(err)
	}
	if l, ok := s.leases.Find(egressLease(addr)); !ok || l.Holder == "another-engine" {
		t.Errorf("this engine does not hold the address: %+v", l)
	}
}

// An engine already working on a job gives its session to another client
// asking for the job's scope on the same database, and the session goes on
// until its last client cancels it.
func TestOneWorkerPerEngine(t *testing.T) {
	dir := t.TempDir()
	cfg := func(domain string) *config.Config {
		c := config.NewConfig()
		c.Dir = dir
		c.Scope = &config.Scope{Domains: []string{domain}}
		return c
	}
	working := cfg("example.com")
	dsn, _, err := primaryDSN(working)
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{id: uuid.New(), cfg: working, dsn: dsn, job: "job-1", work: &coord.Topic{}}
	r := &manager{sessions: map[uuid.UUID]et.Session{s.id: s}, clients: map[uuid.UUID]int{s.id: 1}}

	if r.workingOn(cfg("other.org")) != nil {
		t.Error("a session of another scope was given")
	}
	apart := cfg("example.com")
	apart.SetJoinRunningJobs(false)
	if r.workingOn(apart) != nil {
		t.Error("a session was given to a client that asked not to join")
	}

	got, err := r.NewSession(cfg("EXAMPLE.com"))
	if err != nil || got.ID() != s.id {
		t.Fatalf("NewSession = %v, %v; want the session already working on the job", got, err)
	}
	if j, ok := got.(interface{ Job() (string, bool) }); !ok {
		t.Error("the session given does not report its job")
	} else if job, joined := j.Job(); job != "job-1" || !joined {
		t.Errorf("Job = %s, %v; want job-1, joined", job, joined)
	}
	if r.clients[s.id] != 2 {
		t.Fatalf("%d clients, want 2", r.clients[s.id])
	}

	r.CancelSession(s.id)
	if r.clients[s.id] != 1 || r.GetSession(s.id) == nil {
		t.Errorf("one client's cancel ended the session another still uses (%d clients)", r.clients[s.id])
	}

	// a pool skips the jobs the engine's sessions already work on
	if jobs := r.jobs(); !jobs["job-1"] || len(jobs) != 1 {
		t.Errorf("the engine's jobs = %v", jobs)
	}
}
