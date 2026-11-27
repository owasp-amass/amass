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
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/coord"
	amassdb "github.com/owasp-amass/amass/v5/internal/db"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/neo4j"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
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
	killOnce     sync.Once
	numOfSess    int
	netSemaphore *sessSemaphore
	// nameKinds decides the names that may be a person's or an
	// organization's (setupMainModel), or is nil
	nameKinds et.NameKindDecider
	// breaker stops the main model's deciders asking a failing model, and
	// counts their requests (setupMainModel), or is nil
	breaker *ai.ModelBreaker

	// netUsage counts the session's share of the engine's DNS and data
	// source capacity; the session's context carries it.
	netUsage *et.NetUsage

	// resolvers is the session's own DNS resolver pool when its
	// configuration names resolvers; the session's context carries it.
	// Without one, the session's queries go to the engine's default pool.
	resolvers *amassdns.Resolvers

	// runs records the session as a collection run in the database, when
	// the repository can, and run is that run's ID.
	runs repository.RunRecorder
	run  string

	// job is the job the session works on (jobs.go): its own ID, or a
	// running job's it joined; work and leases are the database's work
	// topic and leases the job's workers share, nil on a database without
	// them; workers are the job's workers seen so far, and left the main
	// model's requests of those that left it, by worker.
	job     string
	joined  bool
	inJob   bool
	work    *coord.Topic
	leases  *coord.Leases
	jobMu   sync.Mutex
	workers []string
	left    map[string]int64
	// renewing counts the goroutine renewing the worker's leases
	renewing sync.WaitGroup
}

// sessionActiveRoute returns the route the session's active traffic takes:
// the configuration's, else the engine's, with the session's ID as the proxy
// isolation key, so each enumeration gets its own Tor circuits.
func sessionActiveRoute(cfg *config.Config, local amassnet.LocalAddrs, id uuid.UUID) (amassnet.Route, error) {
	route := amassnet.ActiveRouteFrom(context.Background())
	if cfg.ActiveRoute != "" || cfg.ActiveUDPRoute != "" {
		r, err := amassnet.ParseRoute(cfg.ActiveRoute, cfg.ActiveUDPRoute)
		if err != nil {
			return amassnet.Route{}, fmt.Errorf("the active route in the configuration: %w", err)
		}
		route = r
	}
	if route.IsZero() {
		return route, nil
	}

	route.Isolation = id.String()
	ctx, cancel := context.WithTimeout(amassnet.WithLocalAddrs(context.Background(), local), 15*time.Second)
	defer cancel()

	if err := route.CheckProxy(ctx, 10*time.Second); err != nil {
		return amassnet.Route{}, err
	}
	return route, nil
}

// CreateSession initializes a new Session object based on the provided configuration.
// The session object represents the state of an active engine enumeration. On a
// database the engines share work through, it joins the running job of its scope,
// if there is one, unless the configuration says not to (config.JoinRunningJobsOption).
func CreateSession(mgr *manager, reg et.Registry, cfg *config.Config) (et.Session, error) {
	s, err := createSession(mgr, reg, cfg, "")
	if err != nil {
		return nil, err
	}
	return s, nil
}

// createSession creates a session that joins the running job named job, when
// given, or otherwise works as CreateSession does.
func createSession(mgr *manager, reg et.Registry, cfg *config.Config, job string) (*Session, error) {
	// Use default configuration if none is provided
	if cfg == nil {
		cfg = config.NewConfig()
	}
	if cfg.Scope == nil {
		return nil, errors.New("the configuration has no scope")
	}

	// the enumeration's own network interface, if it names one; otherwise
	// its traffic leaves from the engine's
	local, err := amassnet.InterfaceAddrs(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("the network interface in the configuration: %w", err)
	}

	// the enumeration's own route for active traffic, if it names one;
	// otherwise the engine's. A proxy that cannot be reached refuses the
	// session, so active traffic is never silently dropped or sent directly.
	id := uuid.New()
	active, err := sessionActiveRoute(cfg, local, id)
	if err != nil {
		return nil, err
	}

	clients, err := NewClients(len(cfg.Scope.Ports), local, active)
	if err != nil {
		return nil, err
	}

	resolvers, err := amassdns.NewSessionResolvers(cfg.Resolvers, cfg.TrustedResolvers, local)
	if err != nil {
		return nil, fmt.Errorf("the DNS resolvers in the configuration: %w", err)
	}

	startTime := time.Now()
	numOfSessions := mgr.NumOfSessions() + 1
	usage := &et.NetUsage{}
	ctx := et.WithNetUsage(context.Background(), usage)
	ctx = amassnet.WithLocalAddrs(ctx, local)
	ctx = amassnet.WithActiveRoute(ctx, active)
	if resolvers != nil {
		ctx = amassdns.WithResolvers(ctx, resolvers)
	}
	ctx = et.WithProbePacer(ctx, probePacer(cfg))
	ctx, cancel := context.WithCancel(ctx)
	// Create a new session object
	s := &Session{
		netUsage:     usage,
		resolvers:    resolvers,
		id:           id,
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
		connectPacer(reg.Log())
	}
	s.log = slog.New(newTeeHandler(slog.NewJSONHandler(s.ps, nil), engineLog)).With("session", s.id)

	err = s.setupDB()
	if err != nil {
		s.Kill()
		return nil, err
	}
	if err := s.setupJob(job); err != nil {
		s.Kill()
		return nil, err
	}
	s.fillCredentials()
	s.shareWork()

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
	s.setupMainModel()
	if !s.cfg.HasExpansionPolicy() {
		s.log.Warn(config.NoPolicyWarning)
	}

	s.log.Info("Session initialized")
	s.log.Info("Temporary directory created", slog.String("dir", s.tmpdir))
	s.log.Info("Database connection established", slog.String("dsn", s.dsn))
	s.startRun()
	s.startJob()
	if s.Done() {
		// the job ended while the session joined it
		return nil, errors.New("the running job of this scope ended while the session joined it")
	}
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
		Bulk:    s.clients.Bulk,
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

// Done reports whether the session has been killed.
func (s *Session) Done() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// Kill ends the session; calls after the first do nothing.
func (s *Session) Kill() {
	s.killOnce.Do(s.kill)
}

func (s *Session) kill() {
	close(s.done)

	// The client may be gone when a session ends, so the engine's own log
	// gets the database calls too.
	s.dbstats.log(s.log)
	s.dbstats.log(s.engineLog())
	s.netUsage.Log(s.log, netUsageMessage)
	s.netUsage.Log(s.engineLog(), netUsageMessage)
	s.leaveJob()
	s.cancel()
	if s.resolvers != nil {
		s.resolvers.Stop()
	}
	s.clients.CloseIdleConnections()
}

func (s *Session) setupDB() error {
	if err := s.selectDBMS(); err != nil {
		return err
	}
	return nil
}

func (s *Session) selectDBMS() error {
	var err error
	if s.dsn, s.dbtype, err = primaryDSN(s.cfg); err != nil {
		return err
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
	// Organizations the engine stored under an earlier name normalization
	// are brought up to the current one before collection starts, so its
	// name lookups find them.
	if n, err := amassdb.NormalizeOrganizationNames(s.ctx, store); err != nil {
		s.log.Warn("organization names were not normalized", slog.String("error", err.Error()))
	} else if n > 0 {
		s.log.Info("organization names normalized", slog.Int("organizations", n))
	}

	s.db, s.dbstats = withDBStats(store)
	return nil
}

// primaryDSN returns the connection string and system of the configuration's
// primary database, a local SQLite database when it names none.
func primaryDSN(cfg *config.Config) (dsn, dbtype string, err error) {
	// If no graph databases are specified, use a default SQLite database.
	if cfg.GraphDBs == nil {
		cfg.GraphDBs = []*config.Database{
			{
				Primary: true,
				System:  "sqlite",
			},
		}
	}
	// Iterate over the GraphDBs specified in the configuration.
	// The goal is to determine the primary database's connection details.
	for _, db := range cfg.GraphDBs {
		if db.Primary {
			// Convert the database system name to lowercase for consistent comparison.
			db.System = strings.ToLower(db.System)

			switch db.System {
			case "postgres":
				// Construct the connection string for a Postgres database.
				dsn = fmt.Sprintf("postgres://%s:%s@%s:%s/%s", db.Username, db.Password, db.Host, db.Port, db.DBName)
				dbtype = postgres.Postgres
			case "sqlite":
				fallthrough
			case "sqlite3":
				// Define the connection path for an SQLite database.
				dsn = filepath.Join(config.OutputDirectory(cfg.Dir), "asset.db")
				dbtype = sqlite3.SQLite
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
				dsn = db.URL
				dbtype = neo4j.Neo4j
			}
			// Break the loop once the primary database is found.
			break
		}
	}
	// Check if a valid database connection string was generated.
	if dsn == "" || dbtype == "" {
		return "", "", errors.New("no primary database specified in the configuration")
	}
	return dsn, dbtype, nil
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
	// the job's other workers' background work is the job's too
	background, done := ss.Background()+s.othersBackground(), ss.BackgroundDone()
	ss.Lock()
	ss.WorkItemsTotal = total + background + done
	ss.WorkItemsCompleted = completed + done
	ss.Unlock()
}
