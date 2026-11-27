// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	"github.com/owasp-amass/amass/v5/internal/coord"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
)

// The kinds of the work topic's job records: a job started, a worker
// joined it, and it ended with its work done or with work left.
const (
	JobKind         = "job"
	JobWorkerKind   = "job_worker"
	JobFinishedKind = "job_finished"
	JobStoppedKind  = "job_stopped"
	// JobLeftKind records a worker leaving a job its other workers go on
	// with, and the main model's requests it made.
	JobLeftKind = "job_left"
)

const (
	// workerLeaseTTL is how long a worker's lease lasts unless renewed;
	// a worker that stops renewing it is gone.
	workerLeaseTTL = time.Minute
	// workerRenewEvery is how often a worker renews its lease, with its
	// count of background work.
	workerRenewEvery = 20 * time.Second
	// jobEndLeaseTTL bounds the lease of the worker ending a job.
	jobEndLeaseTTL = 10 * time.Minute
)

// jobRecord is a job record's data: the scope's fingerprint, the job's
// collection run, and its configuration without database settings or data
// source credentials.
type jobRecord struct {
	Fingerprint string          `json:"fingerprint"`
	Run         string          `json:"run,omitempty"`
	Config      json.RawMessage `json:"config"`
}

// workerRecord is the data of a job_worker, job_left, job_finished or
// job_stopped record: the session it is about, why the job ended, and the
// requests the session's main model was sent.
type workerRecord struct {
	Worker     string `json:"worker"`
	Reason     string `json:"reason,omitempty"`
	ModelCalls int64  `json:"model_calls,omitempty"`
}

// workerData is the data on a worker's lease.
type workerData struct {
	Background int   `json:"background"`
	ModelCalls int64 `json:"model_calls,omitempty"`
}

// job is what the work topic says of one job.
type job struct {
	ID     string
	Record jobRecord
	// Seq is the job record's place in the topic: older jobs have lower
	// numbers.
	Seq     int64
	Workers []string
	Ended   bool
}

// jobKinds are the kinds of the job records findJob, the pool and leaveJob
// read: what jobs there are, their workers and their ends, without the
// jobs' scope and admission records.
var jobKinds = []string{JobKind, JobWorkerKind, JobFinishedKind, JobStoppedKind}

func workerLease(job, worker string) string { return "worker:" + job + ":" + worker }

// egressLease names the lease of the engine working with a database from a
// public address: one engine per address, so the resolvers, data sources
// and targets never see two engines' traffic from one address.
func egressLease(a netip.Addr) string { return "egress:" + a.String() }

// claimEgress takes or renews the lease on the engine's public address,
// when it is known, and reports whether this engine holds it.
func claimEgress(leases *coord.Leases) (string, bool) {
	a, ok := amassnet.Egress()
	if !ok {
		return "", true
	}
	return a.String(), leases.Try(egressLease(a), workerLeaseTTL)
}

// errSecondEngine is the refusal of an engine whose public address another
// engine working with the same database holds.
func errSecondEngine(addr string) error {
	return fmt.Errorf("another engine on this public address (%s) is working with this database; run one engine "+
		"per public address (or wait a minute if that engine has stopped)", addr)
}

func jobEndLease(job string) string { return "job-end:" + job }

// foldJobs adds what the job records among recs say to jobs, by job ID.
func foldJobs(jobs map[string]*job, recs []*dbt.JournalRecord) {
	get := func(id string) *job {
		j := jobs[id]
		if j == nil {
			j = &job{ID: id}
			jobs[id] = j
		}
		return j
	}

	for _, rec := range recs {
		switch rec.Kind {
		case JobKind:
			var jr jobRecord
			if json.Unmarshal(rec.Data, &jr) == nil {
				j := get(rec.Key)
				j.Record, j.Seq = jr, rec.Seq
			}
		case JobWorkerKind:
			var wr workerRecord
			if json.Unmarshal(rec.Data, &wr) == nil && wr.Worker != "" {
				if j := get(rec.Key); !slices.Contains(j.Workers, wr.Worker) {
					j.Workers = append(j.Workers, wr.Worker)
				}
			}
		case JobFinishedKind, JobStoppedKind:
			get(rec.Key).Ended = true
		}
	}
}

// scopeFingerprint names a configuration's scope, so sessions given the
// same scope find the same job, or "" for an empty scope.
func scopeFingerprint(cfg *config.Config) string {
	if cfg == nil || cfg.Scope == nil {
		return ""
	}

	var keys []string
	for _, t := range runScope(cfg.Scope) {
		keys = append(keys, string(t.Type)+"|"+t.Key)
	}
	for _, o := range cfg.Scope.Organizations {
		if o = strings.ToLower(strings.TrimSpace(o)); o != "" {
			keys = append(keys, "Organization|"+o)
		}
	}
	if len(keys) == 0 {
		return ""
	}

	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:])
}

// jobConfig is a configuration as a job record keeps it: without the
// database settings and data source credentials, which each worker brings.
func jobConfig(cfg *config.Config) (json.RawMessage, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	// the database's settings, and its connection string in the options,
	// carry its password
	delete(m, "database")
	if opts, ok := m["options"].(map[string]any); ok {
		delete(opts, "database")
	}
	if dsc, ok := m["datasource_config"].(map[string]any); ok {
		if list, ok := dsc["datasources"].([]any); ok {
			for _, ds := range list {
				if d, ok := ds.(map[string]any); ok {
					delete(d, "creds")
				}
			}
		}
	}
	return json.Marshal(m)
}

// mergeJobConfig is the configuration a worker joining a job uses: the
// job's, with the worker's own database, credentials, network settings and
// AI settings.
func mergeJobConfig(local *config.Config, rec jobRecord) (*config.Config, error) {
	cfg := &config.Config{}
	if err := json.Unmarshal(rec.Config, cfg); err != nil {
		return nil, err
	}
	for k, t := range cfg.Transformations {
		_ = t.Split(k)
	}

	cfg.GraphDBs, cfg.Dir, cfg.EngineAPI, cfg.AI = local.GraphDBs, local.Dir, local.EngineAPI, local.AI
	cfg.Resolvers, cfg.TrustedResolvers = local.Resolvers, local.TrustedResolvers
	cfg.Interface, cfg.ActiveRoute, cfg.ActiveUDPRoute = local.Interface, local.ActiveRoute, local.ActiveUDPRoute
	if cfg.DataSrcConfigs != nil {
		for _, ds := range cfg.DataSrcConfigs.Datasources {
			if ds == nil {
				continue
			}
			ds.Creds = nil
			if l := local.GetDataSourceConfig(ds.Name); l != nil {
				ds.Creds = l.Creds
			}
		}
	}
	return cfg, nil
}

// setupJob makes the session a worker of a job, when the database keeps the
// journal, leases and work queues the workers share: of the running job
// named want, or, without one, of the running job of its scope, whose
// configuration it then takes; otherwise of a new job, its own. A job named
// want that is not running is an error.
func (s *Session) setupJob(want string) error {
	s.job = s.id.String()
	topic, leases := coord.Open(s.db, WorkTopic), coord.OpenLeases(s.db)
	if _, ok := s.db.(repository.WorkQueue); !ok || topic == nil || leases == nil {
		if want != "" {
			return errors.New("the database keeps no jobs to join")
		}
		return nil
	}
	if addr, ok := claimEgress(leases); !ok {
		return errSecondEngine(addr)
	}
	s.work, s.leases = topic, leases
	if want == "" && !s.cfg.JoinsRunningJobs() {
		return nil
	}

	j := s.findJob(want, scopeFingerprint(s.cfg))
	if j == nil {
		if want != "" {
			return fmt.Errorf("job %s is not running", want)
		}
		return nil
	}
	cfg, err := mergeJobConfig(s.cfg, j.Record)
	if err != nil {
		if want != "" {
			return fmt.Errorf("the configuration of job %s: %w", want, err)
		}
		s.log.Warn("the running job's configuration was not read; starting a new job", "job", j.ID,
			slog.String("error", err.Error()))
		return nil
	}

	s.resizeClients(cfg)
	s.cfg, s.job, s.run, s.joined = cfg, j.ID, j.Record.Run, true
	s.scope = scope.CreateFromConfigScope(s)
	s.log.Info("joined the running enumeration of this scope; the job's configuration is used", "job", j.ID)
	return nil
}

// resizeClients rebuilds the session's HTTP clients for the ports cfg
// probes, when they differ from the ports the clients were built for (a
// pool worker's own configuration names none): the probe client allows one
// connection per port to each host. The session's interface and route are
// kept.
func (s *Session) resizeClients(cfg *config.Config) {
	n := 0
	if cfg.Scope != nil {
		n = len(cfg.Scope.Ports)
	}
	if s.clients == nil || s.cfg.Scope == nil || n == len(s.cfg.Scope.Ports) {
		return
	}
	c, err := NewClients(n, amassnet.LocalAddrsFrom(s.ctx), amassnet.ActiveRouteFrom(s.ctx))
	if err != nil {
		s.log.Warn("the HTTP clients were not sized for the job's ports", slog.String("error", err.Error()))
		return
	}
	s.clients.CloseIdleConnections()
	s.clients = c
}

// findJob returns the running job named want, or, without want, the
// running job whose scope has the fingerprint. A job whose workers are all
// gone is ended on the way, and its queue deleted.
func (s *Session) findJob(want, fingerprint string) *job {
	if want == "" && fingerprint == "" {
		return nil
	}
	recs, err := s.work.ReadWhere(dbt.JournalFilter{Kinds: jobKinds}, 0)
	if err != nil {
		return nil
	}
	jobs := map[string]*job{}
	foldJobs(jobs, recs)

	var found *job
	for _, j := range jobs {
		if j.Ended || j.Record.Config == nil {
			continue
		}
		if !s.jobLive(j, "") {
			q, _ := s.db.(repository.WorkQueue)
			if endAbandoned(j, s.work, s.leases, s.runs, q, s.id.String()) {
				s.engineLog().Info("ended a job whose workers all stopped", "job", j.ID)
			}
			continue
		}
		if (want != "" && j.ID == want) || (want == "" && j.Record.Fingerprint == fingerprint) {
			found = j
		}
	}
	return found
}

// jobLive reports whether a worker of the job other than except still holds
// its lease.
func (s *Session) jobLive(j *job, except string) bool {
	for _, w := range j.Workers {
		if w == except {
			continue
		}
		if _, ok := s.leases.Find(workerLease(j.ID, w)); ok {
			return true
		}
	}
	return false
}

// endAbandoned ends a job whose workers all stopped without ending it, and
// reports whether it did: its run is stopped and its queue deleted. by names
// who ended it.
func endAbandoned(j *job, work *coord.Topic, leases *coord.Leases, runs repository.RunRecorder,
	q repository.WorkQueue, by string) bool {
	if !leases.Try(jobEndLease(j.ID), jobEndLeaseTTL) {
		return false
	}
	_, _ = work.Append(JobStoppedKind, j.ID, workerRecord{Worker: by,
		Reason: "every worker stopped without ending the job"})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if runs != nil && j.Record.Run != "" {
		_, _ = runs.FinishRun(ctx, j.Record.Run, dbt.RunStopped, time.Time{})
	}
	if q != nil {
		_ = q.DeleteQueue(ctx, j.ID)
	}
	return true
}

// startJob records a new job, unless the session joined one, and the
// session as one of its workers, holding its worker lease while it runs.
func (s *Session) startJob() {
	if s.work == nil {
		return
	}

	worker := s.id.String()
	s.inJob = true
	s.renewWorker()
	// the worker is recorded before the job, so no engine reading in between
	// takes the new job for one whose workers are gone
	_, _ = s.work.Append(JobWorkerKind, s.job, workerRecord{Worker: worker})
	s.addWorker(worker)
	if !s.joined {
		raw, err := jobConfig(s.cfg)
		if err == nil {
			_, err = s.work.Append(JobKind, s.job, jobRecord{Fingerprint: scopeFingerprint(s.cfg), Run: s.run,
				Config: raw})
		}
		if err != nil {
			s.log.Warn("the job was not recorded; other engines cannot join it", slog.String("error", err.Error()))
		}
	}

	s.renewing.Add(1)
	go func() {
		defer s.renewing.Done()
		t := time.NewTicker(workerRenewEvery)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				s.renewWorker()
			}
		}
	}()
}

// renewWorker takes or renews the session's worker lease, with its count of
// background work and of the main model's requests, and the engine's lease
// on its public address, which expires a minute after the engine's last
// session ends.
func (s *Session) renewWorker() {
	s.leases.TryData(workerLease(s.job, s.id.String()), workerLeaseTTL,
		workerData{Background: s.stats.Background(), ModelCalls: s.breaker.Requests()})
	_, _ = claimEgress(s.leases)
}

// addWorker notes a worker of the session's job.
func (s *Session) addWorker(w string) {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if !slices.Contains(s.workers, w) {
		s.workers = append(s.workers, w)
	}
}

// othersBackground is the background work the job's other live workers
// report.
func (s *Session) othersBackground() int {
	if s.work == nil {
		return 0
	}
	s.jobMu.Lock()
	workers := slices.Clone(s.workers)
	s.jobMu.Unlock()

	var n int
	for _, w := range workers {
		if w == s.id.String() {
			continue
		}
		if l, ok := s.leases.Find(workerLease(s.job, w)); ok {
			var d workerData
			if json.Unmarshal(l.Data, &d) == nil {
				n += d.Background
			}
		}
	}
	return n
}

// applyJobRecords takes the job records among recs: the workers that
// joined, and the job's end, which ends the session.
func (s *Session) applyJobRecords(recs []*dbt.JournalRecord) {
	for _, rec := range recs {
		if rec.Key != s.job {
			continue
		}
		var wr workerRecord
		_ = json.Unmarshal(rec.Data, &wr)
		switch rec.Kind {
		case JobWorkerKind:
			if wr.Worker != "" {
				s.addWorker(wr.Worker)
			}
		case JobLeftKind:
			s.workerLeft(wr)
		case JobFinishedKind, JobStoppedKind:
			if wr.Worker != s.id.String() {
				s.log.Info("the job ended; ending this worker", "job", s.job, "reason", wr.Reason)
				go s.end()
			}
		}
	}
}

// end ends the session for every client of it, as its manager does, or,
// before the manager has it, at once.
func (s *Session) end() {
	if s.mgr != nil && s.mgr.GetSession(s.id) != nil {
		s.mgr.endSession(s.id)
		return
	}
	s.Kill()
}

// leaveJob takes the session out of its job. The last worker to leave ends
// the job: it finishes the run, records the job's end and deletes its
// queue; a worker leaving others behind keeps the queue for them.
func (s *Session) leaveJob() {
	if s.work == nil || !s.inJob {
		// a worker that joined a job leaves its run to the job's workers
		if !s.joined {
			s.finishRun()
		}
		return
	}

	worker := s.id.String()
	// the renewal must not take the lease again after it is released
	s.renewing.Wait()
	s.leases.Release(workerLease(s.job, worker))
	recs, err := s.work.ReadWhere(dbt.JournalFilter{Key: s.job, Kinds: jobKinds}, 0)
	if err != nil {
		// the job's workers cannot be told apart from none, so the job is
		// left to them, or to the next engine that finds it abandoned
		s.log.Warn("the job's workers were not read; leaving the job to them", "job", s.job,
			slog.String("error", err.Error()))
		s.backlog.keepQueue()
		return
	}
	jobs := map[string]*job{}
	foldJobs(jobs, recs)
	if j := jobs[s.job]; j != nil && j.Ended {
		return
	} else if j != nil && s.jobLive(j, worker) {
		s.backlog.keepQueue()
		_, _ = s.work.Append(JobLeftKind, s.job, workerRecord{Worker: worker, ModelCalls: s.breaker.Requests()})
		return
	}
	if !s.leases.Try(jobEndLease(s.job), jobEndLeaseTTL) {
		s.backlog.keepQueue()
		return
	}

	kind, reason := JobStoppedKind, "the last worker stopped with work left"
	if s.finishRun() == dbt.RunFinished {
		kind, reason = JobFinishedKind, ""
	}
	_, _ = s.work.Append(kind, s.job, workerRecord{Worker: worker, Reason: reason, ModelCalls: s.breaker.Requests()})
}

// jobQueue names the session's work queue: its job's.
func (s *Session) jobQueue() string {
	if s.job != "" {
		return s.job
	}
	return s.id.String()
}

// Job returns the ID of the session's job, and whether the session joined
// it rather than starting it.
func (s *Session) Job() (string, bool) {
	return s.job, s.joined
}
