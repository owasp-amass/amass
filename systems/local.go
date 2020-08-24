// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package systems

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"golang.org/x/sync/semaphore"
)

// LocalSystem implements a System to be executed within a single process.
type LocalSystem struct {
	cfg    *config.Config
	pool   resolvers.Resolver
	graphs []*graph.Graph

	// Semaphore to enforce the maximum DNS queries
	semMaxDNSQueries *semaphore.Weighted

	// Broadcast channel that indicates no further writes to the output channel
	done              chan struct{}
	doneAlreadyClosed bool

	addSource  chan requests.Service
	allSources chan chan []requests.Service
}

// NewLocalSystem returns an initialized LocalSystem object.
func NewLocalSystem(c *config.Config) (*LocalSystem, error) {
	if err := c.CheckSettings(); err != nil {
		return nil, err
	}

	pool := resolvers.SetupResolverPool(c.Resolvers, c.MaxDNSQueries, c.MonitorResolverRate, c.Log)
	if pool == nil {
		return nil, errors.New("The system was unable to build the pool of resolvers")
	}

	sys := &LocalSystem{
		cfg:              c,
		pool:             pool,
		done:             make(chan struct{}, 2),
		addSource:        make(chan requests.Service, 10),
		allSources:       make(chan chan []requests.Service, 10),
		semMaxDNSQueries: semaphore.NewWeighted(int64(c.MaxDNSQueries)),
	}

	// Make sure that the output directory is setup for this local system
	if err := sys.setupOutputDirectory(); err != nil {
		sys.Shutdown()
		return nil, err
	}

	// Setup the correct graph database handler
	if err := sys.setupGraphDBs(); err != nil {
		sys.Shutdown()
		return nil, err
	}

	go sys.manageDataSources()
	return sys, nil
}

// Config implements the System interface.
func (l *LocalSystem) Config() *config.Config {
	return l.cfg
}

// Pool implements the System interface.
func (l *LocalSystem) Pool() resolvers.Resolver {
	return l.pool
}

// AddSource implements the System interface.
func (l *LocalSystem) AddSource(src requests.Service) error {
	l.addSource <- src
	return nil
}

// AddAndStart implements the System interface.
func (l *LocalSystem) AddAndStart(srv requests.Service) error {
	err := srv.Start()

	if err == nil {
		return l.AddSource(srv)
	}
	return err
}

// DataSources implements the System interface.
func (l *LocalSystem) DataSources() []requests.Service {
	ch := make(chan []requests.Service, 2)

	l.allSources <- ch
	return <-ch
}

// SetDataSources assigns the data sources that will be used by the system.
func (l *LocalSystem) SetDataSources(sources []requests.Service) {
	// Add all the data sources that successfully start to the list
	for _, src := range sources {
		l.AddAndStart(src)
	}
}

// GraphDatabases implements the System interface.
func (l *LocalSystem) GraphDatabases() []*graph.Graph {
	return l.graphs
}

// Shutdown implements the System interface.
func (l *LocalSystem) Shutdown() error {
	if l.doneAlreadyClosed {
		return nil
	}
	l.doneAlreadyClosed = true

	for _, src := range l.DataSources() {
		src.Stop()
	}
	close(l.done)

	for _, g := range l.GraphDatabases() {
		g.Close()
	}

	go l.pool.Stop()
	return nil
}

// GetAllSourceNames returns the names of all the available data sources.
func (l *LocalSystem) GetAllSourceNames() []string {
	var names []string

	for _, src := range l.DataSources() {
		names = append(names, src.String())
	}
	return names
}

func (l *LocalSystem) setupOutputDirectory() error {
	path := config.OutputDirectory(l.cfg.Dir)
	if path == "" {
		return nil
	}

	var err error
	// If the directory does not yet exist, create it
	if err = os.MkdirAll(path, 0755); err != nil {
		return nil
	}

	return nil
}

// Select the graph that will store the System findings.
func (l *LocalSystem) setupGraphDBs() error {
	cfg := l.Config()

	var dbs []*config.Database
	if db := cfg.LocalDatabaseSettings(cfg.GraphDBs); db != nil {
		dbs = append(dbs, db)
	}
	dbs = append(dbs, cfg.GraphDBs...)

	for _, db := range dbs {
		cayley := graph.NewCayleyGraph(db.System, db.URL, db.Options)
		if cayley == nil {
			return fmt.Errorf("System: Failed to create the %s graph", db.System)
		}

		g := graph.NewGraph(cayley)
		if g == nil {
			return fmt.Errorf("System: Failed to create the %s graph", g.String())
		}

		l.graphs = append(l.graphs, g)
	}

	return nil
}

// GetMemoryUsage returns the number bytes allocated to heap objects on this system.
func (l *LocalSystem) GetMemoryUsage() uint64 {
	var m runtime.MemStats

	runtime.ReadMemStats(&m)
	return m.Alloc
}

// PerformDNSQuery blocks if the maximum number of queries is already taking place.
func (l *LocalSystem) PerformDNSQuery(ctx context.Context) error {
	return l.semMaxDNSQueries.Acquire(ctx, 1)
}

// FinishedDNSQuery allows a new DNS query to be started when at the maximum.
func (l *LocalSystem) FinishedDNSQuery() {
	l.semMaxDNSQueries.Release(1)
}

func (l *LocalSystem) manageDataSources() {
	var dataSources []requests.Service

	for {
		select {
		case <-l.done:
			return
		case add := <-l.addSource:
			dataSources = append(dataSources, add)
		case all := <-l.allSources:
			all <- dataSources
		}
	}
}
