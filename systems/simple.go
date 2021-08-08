// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package systems

import (
	"runtime"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/netmap"
	"github.com/caffix/resolve"
	"github.com/caffix/service"
)

type SimpleSystem struct {
	Cfg      *config.Config
	Resolver resolve.Resolver
	Graph    *netmap.Graph
	ASNCache *requests.ASNCache
	Service  service.Service
}

// Config implements the System interface.
func (ss *SimpleSystem) Config() *config.Config { return ss.Cfg }

// Pool implements the System interface.
func (ss *SimpleSystem) Pool() resolve.Resolver { return ss.Resolver }

// Cache implements the System interface.
func (ss *SimpleSystem) Cache() *requests.ASNCache { return ss.ASNCache }

// AddSource implements the System interface.
func (ss *SimpleSystem) AddSource(src service.Service) error { ss.Service = src; return nil }

// AddAndStart implements the System interface.
func (ss *SimpleSystem) AddAndStart(srv service.Service) error {
	err := srv.Start()

	if err == nil {
		err = ss.AddSource(srv)
	}

	return err
}

// DataSources implements the System interface.
func (ss *SimpleSystem) DataSources() []service.Service { return []service.Service{ss.Service} }

// SetDataSources assigns the data sources that will be used by the system.
func (ss *SimpleSystem) SetDataSources(sources []service.Service) { ss.Service = sources[0] }

// GraphDatabases implements the System interface.
func (ss *SimpleSystem) GraphDatabases() []*netmap.Graph { return []*netmap.Graph{ss.Graph} }

// Shutdown implements the System interface.
func (ss *SimpleSystem) Shutdown() error {
	if ss.Service != nil {
		_ = ss.Service.Stop()
	}
	if ss.Graph != nil {
		ss.Graph.Close()
	}
	if ss.Resolver != nil {
		ss.Resolver.Stop()
	}
	if ss.ASNCache != nil {
		ss.ASNCache = nil
	}
	return nil
}

// GetMemoryUsage returns the number bytes allocated to heap objects on this system.
func (ss *SimpleSystem) GetMemoryUsage() uint64 {
	var m runtime.MemStats

	runtime.ReadMemStats(&m)
	return m.Alloc
}
