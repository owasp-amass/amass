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
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
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
}

// CreateSession initializes a new Session object based on the provided configuration.
// The session object represents the state of an active engine enumeration.
func CreateSession(mgr *manager, reg et.Registry, cfg *config.Config) (et.Session, error) {
	// Use default configuration if none is provided
	if cfg == nil {
		cfg = config.NewConfig()
	}

	clients, err := NewClients(len(cfg.Scope.Ports))
	if err != nil {
		return nil, err
	}

	startTime := time.Now()
	numOfSessions := mgr.NumOfSessions() + 1
	ctx, cancel := context.WithCancel(context.Background())
	// Create a new session object
	s := &Session{
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
		netSemaphore: NewSessSemaphore(amassnet.MaxNetworkConns / numOfSessions),
	}
	s.scope = scope.CreateFromConfigScope(s)
	s.log = slog.New(slog.NewJSONHandler(s.ps, nil)).With("session", s.id)

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
	go s.updateStats()
	go s.updateSessionSemaphore()
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

	s.cancel()
	s.finished = true
	s.clients.CloseIdleConnections()
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
	s.db = store
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
	ss.Lock()
	ss.WorkItemsTotal = total
	ss.WorkItemsCompleted = completed
	ss.Unlock()
}

type sessSemaphore struct {
	sync.Mutex
	sem amassnet.Semaphore
}

func NewSessSemaphore(limit int) *sessSemaphore {
	return &sessSemaphore{sem: amassnet.NewSemaphore(limit)}
}

func (ss *sessSemaphore) Acquire() {
	ss.Lock()
	defer ss.Unlock()

	ss.sem.Acquire()
}

func (ss *sessSemaphore) Release() {
	ss.Lock()
	defer ss.Unlock()

	ss.sem.Release()
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
	s.netSemaphore.Lock()
	defer s.netSemaphore.Unlock()

	limit := amassnet.MaxNetworkConns / s.numOfSess
	sem := amassnet.NewSemaphore(limit)
loop:
	for range limit {
		select {
		case s.netSemaphore.sem <- struct{}{}:
			select {
			case <-sem:
			default:
				break loop
			}
		default:
			break loop
		}
	}

	s.netSemaphore.sem = sem
}
