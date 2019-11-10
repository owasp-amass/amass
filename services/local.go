// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"errors"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/graph/db"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringset"
)

// LocalSystem implements a System to be executed within a single process.
type LocalSystem struct {
	sync.Mutex

	cfg    *config.Config
	pool   resolvers.Resolver
	graphs []*graph.Graph

	// The various services running within the system
	coreSrvs    []Service
	dataSources []Service

	// Broadcast channel that indicates no further writes to the output channel
	done              chan struct{}
	doneAlreadyClosed bool
}

// NewLocalSystem returns an initialized LocalSystem object.
func NewLocalSystem(c *config.Config) (*LocalSystem, error) {
	if err := c.CheckSettings(); err != nil {
		return nil, err
	}

	pool := resolvers.SetupResolverPool(
		c.Resolvers,
		c.ScoreResolvers,
		c.MonitorResolverRate,
		c.Log,
	)
	if pool == nil {
		return nil, errors.New("The system was unable to build the pool of resolvers")
	}

	sys := &LocalSystem{
		cfg:  c,
		pool: pool,
		done: make(chan struct{}, 2),
	}

	// Setup the correct graph database handler
	if err := sys.setupGraphDBs(); err != nil {
		sys.Shutdown()
		return nil, err
	}

	if err := sys.initCoreServices(); err != nil {
		sys.Shutdown()
		return nil, err
	}

	// Add all the data sources that successfully start to the list
	for _, src := range GetAllSources(sys) {
		sys.AddAndStart(src)
	}

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
func (l *LocalSystem) AddSource(srv Service) error {
	l.Lock()
	defer l.Unlock()

	l.dataSources = append(l.dataSources, srv)
	return nil
}

// AddAndStart implements the System interface.
func (l *LocalSystem) AddAndStart(srv Service) error {
	err := srv.Start()

	if err == nil {
		return l.AddSource(srv)
	}
	return err
}

// DataSources implements the System interface.
func (l *LocalSystem) DataSources() []Service {
	l.Lock()
	defer l.Unlock()

	return l.dataSources
}

// CoreServices implements the System interface.
func (l *LocalSystem) CoreServices() []Service {
	l.Lock()
	defer l.Unlock()

	return l.coreSrvs
}

// GraphDatabases implements the System interface.
func (l *LocalSystem) GraphDatabases() []*graph.Graph {
	return l.graphs
}

// Shutdown implements the System interface.
func (l *LocalSystem) Shutdown() error {
	if !l.doneAlreadyClosed {
		l.doneAlreadyClosed = true
		close(l.done)
	}

	for _, src := range l.DataSources() {
		src.Stop()
	}

	for _, srv := range l.CoreServices() {
		srv.Stop()
	}

	for _, g := range l.GraphDatabases() {
		g.Close()
	}

	l.pool.Stop()
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

// Select the graph that will store the System findings.
func (l *LocalSystem) setupGraphDBs() error {
	if l.Config().GremlinURL != "" {
		/*gremlin := graph.NewGremlin(l.Config().GremlinURL,
			l.Config().GremlinUser, l.Config().GremlinPass, l.Config().Log)
		l.graphs = append(l.graphs, gremlin)*/
	}

	g := graph.NewGraph(db.NewCayleyGraph(l.Config().Dir))
	if g == nil {
		return errors.New("Failed to create the graph")
	}
	l.graphs = append(l.graphs, g)
	/*
		if l.Config().DataOptsWriter != nil {
			l.graphs = append(l.graphs,
				graph.NewDataOptsHandler(l.Config().DataOptsWriter))
		}*/
	return nil
}

// Select the correct core services to be used in the System.
func (l *LocalSystem) initCoreServices() error {
	l.coreSrvs = []Service{
		NewDNSService(l),
		NewDataManagerService(l),
	}

	// Start all the core services selected
	for _, srv := range l.coreSrvs {
		if err := srv.Start(); err != nil {
			return err
		}
	}

	return nil
}

func (l *LocalSystem) periodicChecks() {
	filter := stringset.NewStringFilter()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-l.done:
			return
		case <-t.C:
			l.checkTheResolvers(filter)
		}
	}
}

func (l *LocalSystem) checkTheResolvers(filter *stringset.StringFilter) {
	pool := l.Pool().(*resolvers.ResolverPool)

	for _, resolver := range pool.Resolvers {
		if a, err := resolver.Available(); !a && err != nil {
			// Do not print the same message more than once
			if !filter.Duplicate(err.Error()) {
				l.Config().Log.Print(err.Error())
			}
		}
	}
}
