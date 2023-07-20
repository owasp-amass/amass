// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"context"
	"time"

	"github.com/caffix/netmap"
	"github.com/caffix/service"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/resolve"
)

// System is the object type for managing services that perform various reconnaissance activities.
type System interface {
	// Returns the configuration for the enumeration this service supports
	Config() *config.Config

	// Returns the pool that handles queries using untrusted DNS resolvers
	Resolvers() *resolve.Resolvers

	// Returns the pool that handles queries using trusted DNS resolvers
	TrustedResolvers() *resolve.Resolvers

	// Returns the cache populated by the system
	Cache() *requests.ASNCache

	// AddSource appends the provided data source to the slice of sources managed by the System
	AddSource(srv service.Service) error

	// AddAndStart starts the provided data source and then appends it to the slice of sources
	AddAndStart(srv service.Service) error

	// DataSources returns the slice of data sources managed by the System
	DataSources() []service.Service

	// SetDataSources assigns the data sources that will be used by System
	SetDataSources(sources []service.Service) error

	// GraphDatabases return the Graphs used by the System
	GraphDatabases() []*netmap.Graph

	// GetMemoryUsage() returns the number bytes allocated to heap objects on this system
	GetMemoryUsage() uint64

	// Shutdown will shutdown the System
	Shutdown() error
}

// PopulateCache updates the provided System cache with ASN information from the System data sources.
func PopulateCache(ctx context.Context, asn int, sys System) {
	// Send the ASN requests to the data sources
	for _, src := range sys.DataSources() {
		src.Input() <- &requests.ASNRequest{ASN: asn}
		time.Sleep(time.Second)
		select {
		case <-ctx.Done():
		case req := <-src.Output():
			if a, ok := req.(*requests.ASNRequest); ok {
				sys.Cache().Update(a)
			}
		default:
		}
	}
}
