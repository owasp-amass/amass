// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

// ArchiveToday is data source object type that implements the DataSource interface.
type ArchiveToday struct {
	BaseDataSource
	baseURL string
}

// NewArchiveToday returns an initialized ArchiveToday as a DataSource.
func NewArchiveToday(srv core.AmassService) DataSource {
	a := &ArchiveToday{baseURL: "http://archive.is"}

	a.BaseDataSource = *NewBaseDataSource(srv, core.ARCHIVE, "Archive Today")
	return a
}

// Query returns the subdomain names discovered when querying this data source.
func (a *ArchiveToday) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := a.crawl(a.baseURL, domain, sub)
	if err != nil {
		a.Service.Config().Log.Printf("%v", err)
	}
	return names
}

// Subdomains returns true when the data source can query for subdomain names.
func (a *ArchiveToday) Subdomains() bool {
	return true
}
