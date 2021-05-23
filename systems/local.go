// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package systems

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/limits"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/netmap"
	"github.com/caffix/resolve"
	"github.com/caffix/service"
)

// LocalSystem implements a System to be executed within a single process.
type LocalSystem struct {
	Cfg               *config.Config
	pool              resolve.Resolver
	graphs            []*netmap.Graph
	cache             *requests.ASNCache
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

	var pool resolve.Resolver
	if len(c.Resolvers) == 0 {
		pool = publicResolverSetup(c, max)
	} else {
		pool = customResolverSetup(c, max)
	}
	if pool == nil {
		return nil, errors.New("The system was unable to build the pool of resolvers")
	}

	sys := &LocalSystem{
		Cfg:        c,
		pool:       pool,
		cache:      requests.NewASNCache(),
		done:       make(chan struct{}, 2),
		addSource:  make(chan service.Service),
		allSources: make(chan chan []service.Service, 10),
	}

	// Load the ASN information into the cache
	if err := sys.loadCacheData(); err != nil {
		_ = sys.Shutdown()
		return nil, err
	}
	// Make sure that the output directory is setup for this local system
	if err := sys.setupOutputDirectory(); err != nil {
		_ = sys.Shutdown()
		return nil, err
	}
	// Setup the correct graph database handler
	if err := sys.setupGraphDBs(); err != nil {
		_ = sys.Shutdown()
		return nil, err
	}

	go sys.manageDataSources()
	return sys, nil
}

// Config implements the System interface.
func (l *LocalSystem) Config() *config.Config {
	return l.Cfg
}

// Pool implements the System interface.
func (l *LocalSystem) Pool() resolve.Resolver {
	return l.pool
}

// Cache implements the System interface.
func (l *LocalSystem) Cache() *requests.ASNCache {
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
func (l *LocalSystem) GraphDatabases() []*netmap.Graph {
	return l.graphs
}

// Shutdown implements the System interface.
func (l *LocalSystem) Shutdown() error {
	if l.doneAlreadyClosed {
		return nil
	}
	l.doneAlreadyClosed = true

	var wg sync.WaitGroup
	for _, src := range l.DataSources() {
		wg.Add(1)

		go func(s service.Service, w *sync.WaitGroup) {
			defer w.Done()
			_ = s.Stop()
		}(src, &wg)
	}

	wg.Wait()
	close(l.done)

	for _, g := range l.GraphDatabases() {
		g.Close()
	}

	l.pool.Stop()
	l.cache = nil
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
	path := config.OutputDirectory(l.Cfg.Dir)
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
		cayley := netmap.NewCayleyGraph(db.System, db.URL, db.Options)
		if cayley == nil {
			return fmt.Errorf("System: Failed to create the %s graph", db.System)
		}

		g := netmap.NewGraph(cayley)
		if g == nil {
			return fmt.Errorf("System: Failed to create the %s graph", g.String())
		}

		// Load the ASN Cache with all prior knowledge of IP address ranges and ASNs
		//_ = ASNCacheFill(g, l.Cache())

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

func customResolverSetup(cfg *config.Config, max int) resolve.Resolver {
	num := len(cfg.Resolvers)
	if num > max {
		num = max
	}

	if cfg.MaxDNSQueries == 0 {
		cfg.MaxDNSQueries = num * config.DefaultQueriesPerBaselineResolver
	} else if cfg.MaxDNSQueries < num {
		cfg.MaxDNSQueries = num
	}

	rate := cfg.MaxDNSQueries / num
	var trusted []resolve.Resolver
	for _, addr := range cfg.Resolvers {
		if r := resolve.NewBaseResolver(addr, rate, cfg.Log); r != nil {
			trusted = append(trusted, r)
		}
	}

	return resolve.NewResolverPool(trusted, 2*time.Second, nil, 1, cfg.Log)
}

func publicResolverSetup(cfg *config.Config, max int) resolve.Resolver {
	baselines := len(config.DefaultBaselineResolvers)

	num := len(config.PublicResolvers)
	if num > max {
		num = max - baselines
	}

	if cfg.MaxDNSQueries == 0 {
		cfg.MaxDNSQueries = num * config.DefaultQueriesPerPublicResolver
	} else if cfg.MaxDNSQueries < num {
		cfg.MaxDNSQueries = num
	}

	trusted := setupResolvers(config.DefaultBaselineResolvers, baselines, config.DefaultQueriesPerBaselineResolver, cfg.Log)
	if len(trusted) == 0 {
		return nil
	}
	baseline := resolve.NewResolverPool(trusted, time.Second, nil, 1, cfg.Log)

	r := setupResolvers(config.PublicResolvers, max, config.DefaultQueriesPerPublicResolver, cfg.Log)
	return resolve.NewResolverPool(r, 2*time.Second, baseline, 2, cfg.Log)
}

func setupResolvers(addrs []string, max, rate int, log *log.Logger) []resolve.Resolver {
	if len(addrs) <= 0 {
		return nil
	}

	finished := make(chan resolve.Resolver, 10)
	for _, addr := range addrs {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			// Add the default port number to the IP address
			addr = net.JoinHostPort(addr, "53")
		}
		go func(ip string, ch chan resolve.Resolver) {
			if err := resolve.ClientSubnetCheck(ip); err == nil {
				if n := resolve.NewBaseResolver(ip, rate, log); n != nil {
					ch <- n
				}
			}
			ch <- nil
		}(addr, finished)
	}

	l := len(addrs)
	var count int
	var resolvers []resolve.Resolver
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
