// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package systems

import (
	"context"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
)

// System is the object type for managing services that perform various reconnaissance activities.
type System interface {
	// Returns the configuration for the enumeration this service supports
	Config() *config.Config

	// Returns the resolver pool that handles DNS requests
	Pool() resolvers.Resolver

	// AddSource appends the provided data source to the slice of sources managed by the System
	AddSource(srv requests.Service) error

	// AddAndStart starts the provided data source and then appends it to the slice of sources
	AddAndStart(srv requests.Service) error

	// DataSources returns the slice of data sources managed by the System
	DataSources() []requests.Service

	// SetDataSources assigns the data sources that will be used by System
	SetDataSources(sources []requests.Service)

	// GraphDatabases return the Graphs used by the System
	GraphDatabases() []*graph.Graph

	// PerformDNSQuery blocks if the maximum number of queries is already taking place
	PerformDNSQuery(ctx context.Context) error
	FinishedDNSQuery()

	// Shutdown will shutdown the System
	Shutdown() error
}
