// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/service"
	amassnet "github.com/owasp-amass/amass/v4/net"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/amass/v4/resources"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/resolve"
)

// LocalSystem implements a System to be executed within a single process.
type LocalSystem struct {
	Cfg               *config.Config
	pool              *resolve.Resolvers
	trusted           *resolve.Resolvers
	graphs            []*netmap.Graph
	cache             *requests.ASNCache
	done              chan struct{}
	doneAlreadyClosed bool
	addSource         chan service.Service
	allSources        chan chan []service.Service
}

// NewLocalSystem returns an initialized LocalSystem object.
func NewLocalSystem(cfg *config.Config) (*LocalSystem, error) {
	if err := cfg.CheckSettings(); err != nil {
		return nil, err
	}

	trusted, num := trustedResolvers(cfg)
	if trusted == nil || num == 0 {
		return nil, errors.New("the system was unable to build the pool of trusted resolvers")
	}

	pool, num := untrustedResolvers(cfg)
	if pool == nil || num == 0 {
		return nil, errors.New("the system was unable to build the pool of untrusted resolvers")
	}
	if cfg.MaxDNSQueries == 0 {
		cfg.MaxDNSQueries += num * cfg.ResolversQPS
	} else {
		pool.SetMaxQPS(cfg.MaxDNSQueries)
	}
	// set a single name server rate limiter for both resolver pools
	rate := resolve.NewRateTracker()
	trusted.SetRateTracker(rate)
	pool.SetRateTracker(rate)

	sys := &LocalSystem{
		Cfg:        cfg,
		pool:       pool,
		trusted:    trusted,
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
	if err := sys.setupGraphDBs(cfg); err != nil {
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

// Resolvers implements the System interface.
func (l *LocalSystem) Resolvers() *resolve.Resolvers {
	return l.pool
}

// TrustedResolvers implements the System interface.
func (l *LocalSystem) TrustedResolvers() *resolve.Resolvers {
	return l.trusted
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
func (l *LocalSystem) SetDataSources(sources []service.Service) error {
	ch := make(chan error, len(sources))
	// Add all the data sources that successfully start to the list
	for _, src := range sources {
		go func(src service.Service, ch chan error) {
			ch <- l.AddAndStart(src)
		}(src, ch)
	}

	t := time.NewTimer(time.Minute)
	defer t.Stop()

	var err error
loop:
	for i := 0; i < len(sources); i++ {
		select {
		case <-t.C:
			err = errors.New("the data source startup routines timed out")
			break loop
		case <-ch:
		}
	}
	return err
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
	for range l.GraphDatabases() {
		//g.Close()
	}

	l.pool.Stop()
	l.trusted.Stop()
	l.cache = nil
	return nil
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
func (l *LocalSystem) setupGraphDBs(cfg *config.Config) error {
	// Add the local database settings to the configuration
	cfg.GraphDBs = append(cfg.GraphDBs, cfg.LocalDatabaseSettings(cfg.GraphDBs))

	for _, db := range cfg.GraphDBs {
		if db.Primary {
			var g *netmap.Graph

			if db.System == "local" {
				g = netmap.NewGraph(db.System, filepath.Join(config.OutputDirectory(cfg.Dir), "amass.sqlite"), db.Options)
			} else {
				connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s", db.Host, db.Port, db.Username, db.Password, db.DBName)
				g = netmap.NewGraph(db.System, connStr, db.Options)
			}

			if g == nil {
				return fmt.Errorf("System: failed to create the graph for database: %s", db.System)
			}

			l.graphs = append(l.graphs, g)
			break
		}
	}

	if len(l.graphs) == 0 {
		return errors.New("System: no primary databases found to create the graph")
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
	ranges, err := resources.GetIP2ASNData()
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

func trustedResolvers(cfg *config.Config) (*resolve.Resolvers, int) {
	pool := resolve.NewResolvers()
	trusted := config.DefaultBaselineResolvers
	if len(cfg.TrustedResolvers) > 0 {
		trusted = cfg.TrustedResolvers
	}

	_ = pool.AddResolvers(cfg.TrustedQPS, trusted...)
	pool.SetDetectionResolver(cfg.TrustedQPS, "8.8.8.8")

	pool.SetLogger(cfg.Log)
	pool.SetTimeout(2 * time.Second)
	return pool, pool.Len()
}

func untrustedResolvers(cfg *config.Config) (*resolve.Resolvers, int) {
	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = publicResolverAddrs(cfg)
		if len(cfg.Resolvers) == 0 {
			// Failed to use the public DNS resolvers database
			cfg.Resolvers = config.DefaultBaselineResolvers
		}
	}
	cfg.Resolvers = checkAddresses(cfg.Resolvers)

	pool := resolve.NewResolvers()
	pool.SetLogger(cfg.Log)
	if cfg.MaxDNSQueries > 0 {
		pool.SetMaxQPS(cfg.MaxDNSQueries)
	}
	_ = pool.AddResolvers(cfg.ResolversQPS, cfg.Resolvers...)
	pool.SetTimeout(3 * time.Second)
	pool.SetThresholdOptions(&resolve.ThresholdOptions{
		ThresholdValue:      20,
		CountTimeouts:       true,
		CountFormatErrors:   true,
		CountServerFailures: true,
		CountNotImplemented: true,
		CountQueryRefusals:  true,
	})
	pool.ClientSubnetCheck()
	return pool, pool.Len()
}

func publicResolverAddrs(cfg *config.Config) []string {
	addrs := config.PublicResolvers

	if len(config.PublicResolvers) == 0 {
		if err := config.GetPublicDNSResolvers(); err != nil {
			cfg.Log.Printf("%v", err)
		}
		addrs = config.PublicResolvers
	}
	return addrs
}

func checkAddresses(addrs []string) []string {
	ips := []string{}

	for _, addr := range addrs {
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			ip = addr
			port = "53"
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		ips = append(ips, net.JoinHostPort(ip, port))
	}
	return ips
}
