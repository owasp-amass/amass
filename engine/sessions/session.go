// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	afmt "github.com/owasp-amass/amass/v5/internal/afmt"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/yl2chen/cidranger"
)

type Session struct {
	id           uuid.UUID
	mgr          *manager
	ctx          context.Context
	cancel       context.CancelFunc
	log          *slog.Logger
	dbstats      *dbStats
	ps           *pubsub.Logger
	cfg          *config.Config
	scope        et.Scope
	start        time.Time
	db           repository.Repository
	backlog      *sessionBacklog
	pipelines    et.SessionPipelines
	dsn          string
	dbtype       string
	clients      *Clients
	ranger       cidranger.Ranger
	tmpdir       string
	stats        *et.SessionStats
	done         chan struct{}
	finished     bool
	numOfSess    int
	netSemaphore *sessSemaphore

	// netUsage counts the session's share of the engine's DNS and data
	// source capacity; the session's context carries it.
	netUsage *et.NetUsage

	// runs records the session as a collection run in the database, when
	// the repository can, and run is that run's ID.
	runs repository.RunRecorder
	run  string
}

// CreateSession initializes a new Session object based on the provided configuration.
// The session object represents the state of an active engine enumeration.
func CreateSession(mgr *manager, reg et.Registry, cfg *config.Config) (et.Session, error) {
	// Use default configuration if none is provided
	if cfg == nil {
		cfg = config.NewConfig()
	}
	if cfg.Scope == nil {
		return nil, errors.New("the configuration has no scope")
	}

	clients, err := NewClients(len(cfg.Scope.Ports))
	if err != nil {
		return nil, err
	}

	startTime := time.Now()
	numOfSessions := mgr.NumOfSessions() + 1
	usage := &et.NetUsage{}
	ctx := et.WithNetUsage(context.Background(), usage)
	ctx = et.WithProbePacer(ctx, probePacer(cfg))
	ctx, cancel := context.WithCancel(ctx)
	// Create a new session object
	s := &Session{
		netUsage:     usage,
		id:           uuid.New(),
		mgr:          mgr,
		ctx:          ctx,
		cancel:       cancel,
		cfg:          cfg,
		start:        startTime,
		clients:      clients,
		ranger:       NewAmassRanger(),
		ps:           pubsub.NewLogger(),
		stats:        new(et.SessionStats),
		done:         make(chan struct{}),
		numOfSess:    numOfSessions,
		netSemaphore: NewSessSemaphore(sessionConnLimit(numOfSessions)),
	}
	s.scope = scope.CreateFromConfigScope(s)
	// the session's log goes to its subscribers and to the engine's log, so
	// a session started without a client still leaves its record there
	var engineLog slog.Handler
	if reg != nil && reg.Log() != nil {
		engineLog = reg.Log().Handler()
	}
	s.log = slog.New(newTeeHandler(slog.NewJSONHandler(s.ps, nil), engineLog)).With("session", s.id)

	err = s.setupDB()
	if err != nil {
		s.Kill()
		return nil, err
	}

	if err := s.createSessionPipelines(reg); err != nil {
		s.Kill()
		return nil, err
	}

	s.tmpdir, err = s.createTemporaryDir()
	if err != nil {
		s.Kill()
		return nil, err
	}

	s.backlog, err = newSessionBacklog(s)
	if err != nil {
		s.Kill()
		return nil, err
	}
	s.backlog.SetLeaseTTL(0)

	s.log.Info("Session initialized")
	s.log.Info("Temporary directory created", slog.String("dir", s.tmpdir))
	s.log.Info("Database connection established", slog.String("dsn", s.dsn))
	s.startRun()
	go s.updateStats()
	go s.updateSessionSemaphore()
	go s.logNetUsage()
	return s, nil
}

func (s *Session) ID() uuid.UUID {
	return s.id
}

func (s *Session) Ctx() context.Context {
	return s.ctx
}

func (s *Session) Log() *slog.Logger {
	return s.log
}

func (s *Session) PubSub() *pubsub.Logger {
	return s.ps
}

func (s *Session) NetSem() et.SessionSemaphone {
	return s.netSemaphore
}

func (s *Session) Config() *config.Config {
	return s.cfg
}

func (s *Session) Scope() et.Scope {
	return s.scope
}

func (s *Session) StartTime() time.Time {
	return s.start
}

func (s *Session) DB() repository.Repository {
	return s.db
}

func (s *Session) Backlog() et.Backlog {
	return s.backlog
}

func (s *Session) Pipelines() et.SessionPipelines {
	return s.pipelines
}

func (s *Session) Clients() *et.SessionHTTPClients {
	return &et.SessionHTTPClients{
		General: s.clients.General,
		Probe:   s.clients.Probe,
		Crawl:   s.clients.Crawl,
	}
}

func (s *Session) CIDRanger() cidranger.Ranger {
	return s.ranger
}

func (s *Session) TmpDir() string {
	return s.tmpdir
}

func (s *Session) Stats() *et.SessionStats {
	return s.stats
}

func (s *Session) Done() bool {
	return s.finished
}

func (s *Session) Kill() {
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)

	// The client may be gone when a session ends, so the engine's own log
	// gets the database calls too.
	s.dbstats.log(s.log)
	s.dbstats.log(s.engineLog())
	s.netUsage.Log(s.log, netUsageMessage)
	s.netUsage.Log(s.engineLog(), netUsageMessage)
	s.finishRun()
	s.cancel()
	s.finished = true
	s.clients.CloseIdleConnections()
}

// startRun records the session as a collection run: what it was asked to
// collect and how, so a later reader can tell what this enumeration did
// not find. A failure is logged; the enumeration goes on without it.
func (s *Session) startRun() {
	if s.runs == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	run, err := s.runs.StartRun(ctx, &dbt.CollectionRun{Tool: "amass", ToolVersion: afmt.Version,
		ExternalID: s.id.String(), StartedAt: s.start, Scope: runScope(s.cfg.Scope), Metadata: runMetadata(s.cfg)})
	if err != nil {
		s.engineLog().Error("failed to record the collection run", "err", err.Error())
		return
	}

	s.run = run.ID
}

// finishRun ends the session's run: finished when all its work was done,
// stopped when it ended with work left, so a run cut short is never read as
// having looked everywhere.
func (s *Session) finishRun() {
	if s.runs == nil || s.run == "" {
		return
	}

	status := dbt.RunStopped
	s.stats.RLock()
	if s.stats.WorkItemsTotal > 0 && s.stats.WorkItemsCompleted >= s.stats.WorkItemsTotal {
		status = dbt.RunFinished
	}

	s.stats.RUnlock()
	if s.stats.Background() > 0 {
		status = dbt.RunStopped
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := s.runs.FinishRun(ctx, s.run, status, time.Time{}); err != nil {
		s.engineLog().Error("failed to finish the collection run", "run", s.run, "err", err.Error())
	}
}

// runScope names a configuration's scope as Open Asset Model targets.
func runScope(sc *config.Scope) []dbt.RunTarget {
	if sc == nil {
		return nil
	}

	var out []dbt.RunTarget
	for _, d := range sc.Domains {
		out = append(out, dbt.RunTarget{Type: oam.FQDN, Key: strings.ToLower(d)})
	}
	for _, ip := range sc.Addresses {
		out = append(out, dbt.RunTarget{Type: oam.IPAddress, Key: ip.String()})
	}
	for _, c := range sc.CIDRs {
		out = append(out, dbt.RunTarget{Type: oam.Netblock, Key: c.String()})
	}
	for _, asn := range sc.ASNs {
		out = append(out, dbt.RunTarget{Type: oam.AutonomousSystem, Key: strconv.Itoa(asn)})
	}

	return out
}

// runMetadata records how the enumeration collected.
func runMetadata(cfg *config.Config) map[string]any {
	mode := "default"
	switch {
	case cfg.Active:
		mode = "active"
	case cfg.Passive:
		mode = "passive"
	}

	return map[string]any{"mode": mode, "rigid": cfg.Rigid, "brute_forcing": cfg.BruteForcing,
		"alterations": cfg.Alterations}
}

// Probe pacing defaults, in milliseconds: an active-enumeration probe to a
// host is held until at least defaultProbePaceMS has passed since the
// previous probe to that host, plus up to defaultProbeJitterMS of random
// spread. The default is modest so that, with many hosts probed at once, an
// enumeration keeps its pace while no single host sees a simultaneous burst
// across ports. The options "probe_pace_ms" and "probe_jitter_ms" override
// them, and a pace of 0 turns pacing off.
const (
	defaultProbePaceMS   = 500
	defaultProbeJitterMS = 1500
)

// probePacer builds a session's probe pacer from its configuration.
func probePacer(cfg *config.Config) *et.ProbePacer {
	pace := optionMS(cfg, "probe_pace_ms", defaultProbePaceMS)
	jitter := optionMS(cfg, "probe_jitter_ms", defaultProbeJitterMS)
	return et.NewProbePacer(time.Duration(pace)*time.Millisecond, time.Duration(jitter)*time.Millisecond)
}

// optionMS reads a non-negative millisecond option, falling back to def when
// it is absent or not a non-negative number.
func optionMS(cfg *config.Config, name string, def int) int {
	if cfg == nil || cfg.Options == nil {
		return def
	}

	switch v := cfg.Options[name].(type) {
	case int:
		if v >= 0 {
			return v
		}
	case int64:
		if v >= 0 {
			return int(v)
		}
	case float64:
		if v >= 0 {
			return int(v)
		}
	}

	return def
}

// netUsageMessage begins the log lines with a session's share of the
// engine's DNS queries and data source rate limits.
const netUsageMessage = "shared network use"

// netUsageEvery is how often a running session logs its shared network use,
// so sessions that run at the same time can be compared while they run.
var netUsageEvery = 10 * time.Minute

// engineLog is the engine's own log, which the engine writes to its
// configured destination (syslog in the Docker setup), with the session's
// ID; slog.Default writes to the engine's standard output.
func (s *Session) engineLog() *slog.Logger {
	l := slog.Default()
	if s.mgr != nil && s.mgr.logger != nil {
		l = s.mgr.logger
	}

	return l.With("session", s.id.String())
}

func (s *Session) logNetUsage() {
	tick := time.NewTicker(netUsageEvery)
	defer tick.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.netUsage.Log(s.engineLog(), netUsageMessage+" so far")
		}
	}
}

func (s *Session) setupDB() error {
	if err := s.selectDBMS(); err != nil {
		return err
	}
	return nil
}

func (s *Session) selectDBMS() error {
	// If no graph databases are specified, use a default SQLite database.
	if s.cfg.GraphDBs == nil {
		s.cfg.GraphDBs = []*config.Database{
			{
				Primary: true,
				System:  "sqlite",
			},
		}
	}
	// Iterate over the GraphDBs specified in the configuration.
	// The goal is to determine the primary database's connection details.
	for _, db := range s.cfg.GraphDBs {
		if db.Primary {
			// Convert the database system name to lowercase for consistent comparison.
			db.System = strings.ToLower(db.System)

			switch db.System {
			case "postgres":
				// Construct the connection string for a Postgres database.
				s.dsn = fmt.Sprintf("postgres://%s:%s@%s:%s/%s", db.Username, db.Password, db.Host, db.Port, db.DBName)
				s.dbtype = postgres.Postgres
			case "sqlite":
				fallthrough
			case "sqlite3":
				// Define the connection path for an SQLite database.
				s.dsn = filepath.Join(config.OutputDirectory(s.cfg.Dir), "asset.db")
				s.dbtype = sqlite3.SQLite
			case "neo4j":
				fallthrough
			case "neo4+s":
				fallthrough
			case "neo4j+sec":
				fallthrough
			case "bolt":
				fallthrough
			case "bolt+s":
				fallthrough
			case "bolt+sec":
				s.dsn = db.URL
				s.dbtype = neo4j.Neo4j
			}
			// Break the loop once the primary database is found.
			break
		}
	}
	// Check if a valid database connection string was generated.
	if s.dsn == "" || s.dbtype == "" {
		return errors.New("no primary database specified in the configuration")
	}
	// Initialize the database store
	store, err := assetdb.New(s.dbtype, s.dsn)
	if err != nil {
		return errors.New("failed to initialize database store: " + err.Error())
	}
	// The database records the first sighting of an asset, edge or tag in
	// this enumeration, and may skip repeats with nothing new: last-seen
	// times stay exact relative to the session's start.
	if seen, ok := store.(repository.SeenSince); ok {
		seen.SetSeenSince(s.start)
	}
	if runs, ok := store.(repository.RunRecorder); ok {
		s.runs = runs
	}

	s.db, s.dbstats = withDBStats(store)
	return nil
}

func (s *Session) createTemporaryDir() (string, error) {
	outdir := config.OutputDirectory()
	if outdir == "" {
		return "", errors.New("failed to obtain the output directory")
	}

	dir, err := os.MkdirTemp(outdir, "session-"+s.ID().String())
	if err != nil {
		return "", errors.New("failed to create the temp dir")
	}

	return dir, nil
}

func (s *Session) createSessionPipelines(reg et.Registry) error {
	s.pipelines = make(et.SessionPipelines, len(oam.AssetList))

	for _, atype := range oam.AssetList {
		p, err := reg.BuildAssetPipeline(s.Ctx(), atype)
		if err != nil {
			return err
		}
		s.pipelines[atype] = p
	}

	return nil
}

func (s *Session) updateStats() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.calculateStats()
		}
	}
}

func (s *Session) calculateStats() {
	var completed, total int

	for _, atype := range oam.AssetList {
		if queued, leased, done, err := s.backlog.Counts(atype); err == nil {
			comp := int(done)
			completed += comp
			total += comp + int(queued) + int(leased)
		}
	}

	ss := s.stats
	background := ss.Background()
	ss.Lock()
	ss.WorkItemsTotal = total + background
	ss.WorkItemsCompleted = completed
	ss.Unlock()
}

// sessSemaphore limits a session's network connections. The limit is the
// engine's share for the session and changes as other sessions start and
// end, so the channel behind it is replaced. Waiting for a slot happens
// outside the lock: a caller blocked while holding it would keep every
// holder from releasing, and the session would stop for good.
type sessSemaphore struct {
	sync.Mutex
	sem amassnet.Semaphore
}

func NewSessSemaphore(limit int) *sessSemaphore {
	return &sessSemaphore{sem: amassnet.NewSemaphore(limit)}
}

// Acquire waits for a slot. A resize closes the channel being waited on,
// and the caller then waits on the new one.
func (ss *sessSemaphore) Acquire() {
	for {
		ss.Lock()
		sem := ss.sem
		ss.Unlock()

		if _, ok := <-sem; ok {
			return
		}
	}
}

// Release returns a slot. It never blocks, so it holds the lock, which keeps
// it from sending on a channel a resize has closed.
func (ss *sessSemaphore) Release() {
	ss.Lock()
	defer ss.Unlock()

	ss.sem.Release()
}

// resize replaces the semaphore with one of limit slots, less those already
// held, and moves the callers waiting on the old one to it.
func (ss *sessSemaphore) resize(limit int) {
	ss.Lock()
	defer ss.Unlock()

	old := ss.sem
	held := cap(old) - len(old)
	// Drain the old channel so no caller takes a stale slot from it once it
	// is closed; closing it wakes the callers waiting on it. The drain never
	// blocks: a caller may take a slot from it meanwhile.
drain:
	for {
		select {
		case <-old:
		default:
			break drain
		}
	}

	sem := amassnet.NewSemaphore(limit)
	for range min(held, limit) {
		<-sem
	}

	ss.sem = sem
	close(old)
}

func (s *Session) updateSessionSemaphore() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			if num := s.mgr.NumOfSessions(); num != s.numOfSess {
				s.numOfSess = num
				s.buildNewSessionSemaphore()
			}
		}
	}
}

func (s *Session) buildNewSessionSemaphore() {
	s.netSemaphore.resize(sessionConnLimit(s.numOfSess))
}

// sessionConnLimit is a session's share of the engine's network
// connections, at least one so the session can always make progress.
func sessionConnLimit(sessions int) int {
	return max(1, amassnet.MaxNetworkConns/max(1, sessions))
}
