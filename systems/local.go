// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package systems

import (
	"errors"
	"sync"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/graphdb"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
)

// LocalSystem implements a System to be executed within a single process.
type LocalSystem struct {
	sync.Mutex

	cfg    *config.Config
	pool   resolvers.Resolver
	graphs []*graph.Graph

	// The various services running within the system
	dataSources []requests.Service

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
func (l *LocalSystem) AddSource(srv requests.Service) error {
	l.Lock()
	defer l.Unlock()

	l.dataSources = append(l.dataSources, srv)
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
	l.Lock()
	defer l.Unlock()

	return l.dataSources
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
	if !l.doneAlreadyClosed {
		l.doneAlreadyClosed = true
		close(l.done)
	}

	for _, src := range l.DataSources() {
		src.Stop()
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

	g := graph.NewGraph(graphdb.NewCayleyGraph(l.Config().Dir))
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
