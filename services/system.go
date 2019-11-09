// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/resolvers"
)

// System is the object type for managing services that perform various reconnaissance activities.
type System interface {
	// Returns the configuration for the enumeration this service supports
	Config() *config.Config

	// Returns the resolver pool that handles DNS requests
	Pool() resolvers.Resolver

	// AddSource appends the provided data source to the slice of sources managed by the System
	AddSource(srv Service) error

	// AddAndStart starts the provided data source and then appends it to the slice of sources
	AddAndStart(srv Service) error

	// DataSources returns the slice of data sources managed by the System
	DataSources() []Service

	// CoreServices returns the slice of core services managed by the System
	CoreServices() []Service

	// GraphDatabases return the Graphs used by the System
	GraphDatabases() []*graph.Graph

	// Shutdown will shutdown the System
	Shutdown() error
}
