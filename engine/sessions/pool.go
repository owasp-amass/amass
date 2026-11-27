// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/coord"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
)

const (
	// poolInterval is how often a pool engine looks for work.
	poolInterval = 15 * time.Second
	// poolDrainedChecks is how many checks in a row a pool worker's job must
	// show no work left before the worker leaves it, as amass enum waits.
	poolDrainedChecks = 5
	// DefaultWorkerSessions is how many jobs a pool engine works on at once
	// unless told otherwise: one session for each.
	DefaultWorkerSessions = 5
)

// pool is a pool engine's state: the database the jobs are found in, the
// configuration its workers bring (database, credentials, network), and
// its workers, by session, with how many checks in a row each job showed
// no work left.
type pool struct {
	mgr     *manager
	cfg     *config.Config
	size    int
	work    *coord.Topic
	leases  *coord.Leases
	queue   repository.WorkQueue
	runs    repository.RunRecorder
	drained map[uuid.UUID]int
}

// StartPool makes the engine a pool worker until ctx ends: it joins running
// jobs on the database cfg names, one session for each, up to size jobs at
// once (DefaultWorkerSessions when size is below 1), choosing the job with
// the most queued work per worker that is below its cap on workers
// (config.MaxJobWorkersOption), and leaves a job once it has no work left. A job one of the engine's other sessions works on is not joined
// again. Its workers use cfg's database, data source credentials and network
// settings, and each job's own configuration otherwise.
func StartPool(ctx context.Context, mgr et.SessionManager, cfg *config.Config, size int) error {
	m, ok := mgr.(*manager)
	if !ok || cfg == nil {
		return errors.New("the engine cannot run as a pool worker")
	}
	if size < 1 {
		size = DefaultWorkerSessions
	}

	dsn, dbtype, err := primaryDSN(cfg)
	if err != nil {
		return err
	}
	store, err := assetdb.New(dbtype, dsn)
	if err != nil {
		return err
	}
	q, ok := store.(repository.WorkQueue)
	topic, leases := coord.Open(store, WorkTopic), coord.OpenLeases(store)
	if !ok || topic == nil || leases == nil {
		_ = store.Close()
		return errors.New("pool workers need a PostgreSQL or SQLite Asset Database")
	}
	if addr, ok := claimEgress(leases); !ok {
		_ = store.Close()
		return errSecondEngine(addr)
	}
	// a pool worker's session takes its job's scope
	if cfg.Scope == nil {
		cfg.Scope = &config.Scope{}
	}

	runs, _ := store.(repository.RunRecorder)
	p := &pool{mgr: m, cfg: cfg, size: size, work: topic, leases: leases, queue: q, runs: runs,
		drained: map[uuid.UUID]int{}}
	go func() {
		defer func() { _ = store.Close() }()
		t := time.NewTicker(poolInterval)
		defer t.Stop()
		renew := time.NewTicker(workerRenewEvery)
		defer renew.Stop()
		for check := true; ; {
			if check {
				p.check(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-renew.C:
				// the pool holds the engine's public address while it runs
				_, _ = claimEgress(leases)
				check = false
			case <-t.C:
				check = true
			}
		}
	}()
	return nil
}

// check retires the workers whose jobs have no work left, and joins another
// job when the pool has room.
func (p *pool) check(ctx context.Context) {
	for id := range p.drained {
		s, ok := p.mgr.GetSession(id).(*Session)
		if !ok || s == nil {
			delete(p.drained, id)
			continue
		}
		if st := s.Stats(); drained(st) {
			p.drained[id]++
		} else {
			p.drained[id] = 0
		}
		if p.drained[id] >= poolDrainedChecks {
			delete(p.drained, id)
			go p.mgr.CancelSession(id)
		}
	}
	if len(p.drained) >= p.size {
		return
	}

	j := p.choose(ctx, p.mgr.jobs())
	if j == "" {
		return
	}
	s, err := createSession(p.mgr, p.mgr.registry, p.cfg, j)
	if err != nil {
		p.mgr.logger.Warn("the pool worker did not join the job", "job", j, "error", err.Error())
		return
	}
	if err := p.mgr.AddSession(s); err != nil {
		p.mgr.logger.Warn("the pool worker did not join the job", "job", j, "error", err.Error())
		return
	}
	p.drained[s.id] = 0
	p.mgr.logger.Info("the pool worker joined a job", "job", j, "session", s.id.String())
}

// choose returns the running job, other than those the pool works on and
// those at their cap on workers, with the most queued work per live worker
// (the older job on a tie), or "" when none has queued work. A job whose
// workers are all gone is ended on the way.
func (p *pool) choose(ctx context.Context, working map[string]bool) string {
	recs, err := p.work.ReadWhere(dbt.JournalFilter{Kinds: jobKinds}, 0)
	if err != nil {
		return ""
	}
	jobs := map[string]*job{}
	foldJobs(jobs, recs)

	var best *job
	var most float64
	for _, j := range jobs {
		if j.Ended || j.Record.Config == nil || working[j.ID] {
			continue
		}
		live := 0
		for _, w := range j.Workers {
			if _, ok := p.leases.Find(workerLease(j.ID, w)); ok {
				live++
			}
		}
		if live == 0 {
			// its workers all stopped without ending it
			if endAbandoned(j, p.work, p.leases, p.runs, p.queue, "pool") {
				p.mgr.logger.Info("the pool ended a job whose workers all stopped", "job", j.ID)
			}
			continue
		}
		if limit := jobMaxWorkers(j.Record.Config); limit > 0 && live >= limit {
			continue
		}
		byKind, err := p.queue.CountWorkByKind(ctx, j.ID)
		c := byKind.Total()
		if err != nil || c.Queued == 0 {
			continue
		}
		per := float64(c.Queued) / float64(live)
		if best == nil || per > most || (per == most && j.Seq < best.Seq) {
			best, most = j, per
		}
	}
	if best == nil {
		return ""
	}
	return best.ID
}

// jobMaxWorkers is the cap on a job's workers that its configuration sets,
// or 0 for none.
func jobMaxWorkers(raw json.RawMessage) int {
	var c struct {
		Options map[string]interface{} `json:"options"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return 0
	}
	return (&config.Config{Options: c.Options}).MaxJobWorkers()
}

// drained reports whether a session's job shows no work left.
func drained(st *et.SessionStats) bool {
	if st == nil {
		return false
	}
	st.RLock()
	defer st.RUnlock()
	return st.WorkItemsTotal > 0 && st.WorkItemsCompleted >= st.WorkItemsTotal
}
