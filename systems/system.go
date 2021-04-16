// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package systems

import (
	"context"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	eb "github.com/caffix/eventbus"
	"github.com/caffix/netmap"
	"github.com/caffix/resolve"
	"github.com/caffix/service"
)

// System is the object type for managing services that perform various reconnaissance activities.
type System interface {
	// Returns the configuration for the enumeration this service supports
	Config() *config.Config

	// Returns the resolver pool that handles DNS requests
	Pool() resolve.Resolver

	// Returns the cache populated by the system
	Cache() *requests.ASNCache

	// AddSource appends the provided data source to the slice of sources managed by the System
	AddSource(srv service.Service) error

	// AddAndStart starts the provided data source and then appends it to the slice of sources
	AddAndStart(srv service.Service) error

	// DataSources returns the slice of data sources managed by the System
	DataSources() []service.Service

	// SetDataSources assigns the data sources that will be used by System
	SetDataSources(sources []service.Service)

	// GraphDatabases return the Graphs used by the System
	GraphDatabases() []*netmap.Graph

	// GetMemoryUsage() returns the number bytes allocated to heap objects on this system
	GetMemoryUsage() uint64

	// Shutdown will shutdown the System
	Shutdown() error
}

// PopulateCache updates the provided System cache with ASN information from the System data sources.
func PopulateCache(ctx context.Context, asn int, sys System) {
	bus := eb.NewEventBus()
	defer bus.Stop()

	cache := sys.Cache()
	bus.Subscribe(requests.NewASNTopic, cache.Update)
	defer bus.Unsubscribe(requests.NewASNTopic, cache.Update)

	ctx = context.WithValue(ctx, requests.ContextConfig, sys.Config())
	ctx = context.WithValue(ctx, requests.ContextEventBus, bus)

	// Send the ASN requests to the data sources
	for _, src := range sys.DataSources() {
		src.Request(ctx, &requests.ASNRequest{ASN: asn})
	}

	// Wait for the ASN requests to return responses
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
