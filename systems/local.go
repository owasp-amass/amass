// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package systems

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/limits"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/caffix/service"
	"github.com/miekg/dns"
)

// LocalSystem implements a System to be executed within a single process.
type LocalSystem struct {
	cfg               *config.Config
	pool              resolvers.Resolver
	graphs            []*graph.Graph
	cache             *amassnet.ASNCache
	done              chan struct{}
	doneAlreadyClosed bool
	addSource         chan service.Service
	allSources        chan chan []service.Service
}

// NewLocalSystem returns an initialized LocalSystem object.
func NewLocalSystem(c *config.Config) (*LocalSystem, error) {
	if err := c.CheckSettings(); err != nil {
		return nil, err
	}

	max := int(float64(limits.GetFileLimit()) * 0.7)
	num := len(config.PublicResolvers)
	if num > max {
		num = max
	}

	rate := c.MaxDNSQueries / len(c.Resolvers)
	var trusted []resolvers.Resolver
	for _, addr := range c.Resolvers {
		trusted = append(trusted, resolvers.NewBaseResolver(addr, rate, c.Log))
	}

	baseline := resolvers.NewResolverPool(trusted, time.Minute, nil, c.Log)
	r := setupResolvers(config.PublicResolvers, max, config.DefaultQueriesPerResolver, c.Log)
	pool := resolvers.NewResolverPool(r, 5*time.Second, baseline, c.Log)
	if pool == nil {
		return nil, errors.New("The system was unable to build the pool of resolvers")
	}

	sys := &LocalSystem{
		cfg:        c,
		pool:       pool,
		cache:      amassnet.NewASNCache(),
		done:       make(chan struct{}, 2),
		addSource:  make(chan service.Service),
		allSources: make(chan chan []service.Service, 10),
	}

	// Load the ASN information into the cache
	if err := sys.loadCacheData(); err != nil {
		sys.Shutdown()
		return nil, err
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

// Cache implements the System interface.
func (l *LocalSystem) Cache() *amassnet.ASNCache {
	return l.cache
}

// AddSource implements the System interface.
func (l *LocalSystem) AddSource(src service.Service) error {
	l.addSource <- src
	return nil
}

// AddAndStart implements the System interface.
func (l *LocalSystem) AddAndStart(srv service.Service) error {
	err := srv.Start()

	if err == nil {
		return l.AddSource(srv)
	}
	return err
}

// DataSources implements the System interface.
func (l *LocalSystem) DataSources() []service.Service {
	ch := make(chan []service.Service, 2)

	l.allSources <- ch
	return <-ch
}

// SetDataSources assigns the data sources that will be used by the system.
func (l *LocalSystem) SetDataSources(sources []service.Service) {
	f := func(src service.Service, ch chan error) { ch <- l.AddAndStart(src) }

	ch := make(chan error, len(sources))
	// Add all the data sources that successfully start to the list
	for _, src := range sources {
		go f(src, ch)
	}

	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
loop:
	for i := 0; i < len(sources); i++ {
		select {
		case <-t.C:
			break loop
		case <-ch:
		}
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

	//go l.pool.Stop()
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

		// Load the ASN Cache with all prior knowledge of IP address ranges and ASNs
		g.ASNCacheFill(l.Cache())

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

func (l *LocalSystem) manageDataSources() {
	var dataSources []service.Service

	for {
		select {
		case <-l.done:
			return
		case add := <-l.addSource:
			dataSources = append(dataSources, add)
			sort.Slice(dataSources, func(i, j int) bool {
				return dataSources[i].String() < dataSources[j].String()
			})
		case all := <-l.allSources:
			all <- dataSources
		}
	}
}

func (l *LocalSystem) loadCacheData() error {
	ranges, err := config.GetIP2ASNData()
	if err != nil {
		return err
	}

	for _, r := range ranges {
		cidr := amassnet.Range2CIDR(r.FirstIP, r.LastIP)
		if cidr == nil {
			continue
		}
		if ones, _ := cidr.Mask.Size(); ones == 0 {
			continue
		}

		l.cache.Update(&requests.ASNRequest{
			Address:     r.FirstIP.String(),
			ASN:         r.ASN,
			CC:          r.CC,
			Prefix:      cidr.String(),
			Description: r.Description,
		})
	}

	return nil
}

func setupResolvers(addrs []string, max, rate int, log *log.Logger) []resolvers.Resolver {
	if len(addrs) <= 0 {
		return nil
	}

	finished := make(chan resolvers.Resolver, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, addr := range addrs {
		go func(ip string, ch chan resolvers.Resolver) {
			if n := resolvers.NewBaseResolver(ip, rate, log); n != nil {
				msg := resolvers.QueryMsg("www.owasp.org", dns.TypeA)

				if resp, err := n.Query(ctx, msg, resolvers.PriorityCritical,
					func(times int, priority int, msg *dns.Msg) bool {
						return msg.Rcode == resolvers.TimeoutRcode && times < 3
					}); err == nil && resp != nil && len(resp.Answer) > 0 {
					ch <- n
					return
				}
			}
			ch <- nil
		}(addr, finished)
	}

	l := len(addrs)
	var count int
	var resolvers []resolvers.Resolver
	for i := 0; i < l; i++ {
		if r := <-finished; r != nil {
			if count < max {
				resolvers = append(resolvers, r)
				count++
				continue
			}
			r.Stop()
		}
	}

	if len(resolvers) == 0 {
		return nil
	}
	return resolvers
}
