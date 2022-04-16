// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"errors"
	"fmt"
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
	"github.com/OWASP/Amass/v3/resources"
	"github.com/caffix/netmap"
	"github.com/caffix/resolve"
	"github.com/caffix/service"
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

	var set bool
	if cfg.MaxDNSQueries == 0 {
		set = true
	}

	max := int(float64(limits.GetFileLimit()) * 0.7)
	trusted, num := trustedResolvers(cfg, max)
	if trusted == nil {
		return nil, errors.New("the system was unable to build the pool of trusted resolvers")
	}
	max -= num
	if set {
		cfg.MaxDNSQueries += num * cfg.TrustedQPS
	}

	pool, num := untrustedResolvers(cfg, max)
	if pool == nil {
		return nil, errors.New("the system was unable to build the pool of untrusted resolvers")
	}
	if set {
		cfg.MaxDNSQueries += num * cfg.ResolversQPS
	} else {
		pool.SetMaxQPS(cfg.MaxDNSQueries)
	}

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
	f := func(src service.Service, ch chan error) { ch <- l.AddAndStart(src) }

	ch := make(chan error, len(sources))
	// Add all the data sources that successfully start to the list
	for _, src := range sources {
		go f(src, ch)
	}

	t := time.NewTimer(30 * time.Second)
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
	for _, g := range l.GraphDatabases() {
		g.Close()
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

func trustedResolvers(cfg *config.Config, max int) (*resolve.Resolvers, int) {
	var num int
	pool := resolve.NewResolvers()

	if len(cfg.TrustedResolvers) > 0 {
		num = len(cfg.TrustedResolvers)
		_ = pool.AddResolvers(cfg.TrustedQPS, cfg.TrustedResolvers...)
	} else {
		num = len(config.DefaultBaselineResolvers)
		_ = pool.AddResolvers(cfg.TrustedQPS, config.DefaultBaselineResolvers...)
		pool.SetDetectionResolver(cfg.TrustedQPS, "8.8.8.8")
	}

	pool.SetLogger(cfg.Log)
	return pool, num
}

func untrustedResolvers(cfg *config.Config, max int) (*resolve.Resolvers, int) {
	if max <= 0 {
		return nil, 0
	}
	if len(cfg.Resolvers) == 0 {
		if pool, num := publicResolverSetup(cfg, max); num > 0 {
			return pool, num
		}
		// Failed to use the public DNS resolvers database
		cfg.Resolvers = config.DefaultBaselineResolvers
	}
	return customResolverSetup(cfg, max)
}

func customResolverSetup(cfg *config.Config, max int) (*resolve.Resolvers, int) {
	num := len(cfg.Resolvers)
	if num > max {
		num = max
		cfg.Resolvers = cfg.Resolvers[:num]
	}

	pool := resolve.NewResolvers()
	pool.SetLogger(cfg.Log)
	_ = pool.AddResolvers(cfg.ResolversQPS, cfg.Resolvers...)
	pool.SetThresholdOptions(&resolve.ThresholdOptions{
		ThresholdValue:      200,
		CountTimeouts:       true,
		CountServerFailures: true,
		CountQueryRefusals:  true,
	})
	return pool, num
}

func publicResolverSetup(cfg *config.Config, max int) (*resolve.Resolvers, int) {
	addrs := config.PublicResolvers
	num := len(config.PublicResolvers)

	if num == 0 {
		if err := config.GetPublicDNSResolvers(); err != nil {
			cfg.Log.Printf("%v", err)
			return nil, 0
		}
		addrs = config.PublicResolvers
		num = len(config.PublicResolvers)
	}
	if num > max {
		num = max
		addrs = addrs[:num]
	}

	addrs = checkAddresses(addrs)
	addrs = runSubnetChecks(addrs)

	r := resolve.NewResolvers()
	r.SetLogger(cfg.Log)
	_ = r.AddResolvers(cfg.ResolversQPS, addrs...)
	r.SetThresholdOptions(&resolve.ThresholdOptions{
		ThresholdValue:      100,
		CountTimeouts:       true,
		CountFormatErrors:   true,
		CountServerFailures: true,
		CountNotImplemented: true,
		CountQueryRefusals:  true,
	})
	return r, len(addrs)
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

func runSubnetChecks(addrs []string) []string {
	finished := make(chan string, 10)

	for _, addr := range addrs {
		go func(ip string, ch chan string) {
			if err := resolve.ClientSubnetCheck(ip); err == nil {
				ch <- ip
				return
			}
			ch <- ""
		}(addr, finished)
	}

	l := len(addrs)
	var ips []string
	for i := 0; i < l; i++ {
		if ip := <-finished; ip != "" {
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return addrs
	}
	return ips
}
