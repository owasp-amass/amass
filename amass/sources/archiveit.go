// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

// ArchiveIt is data source object type that implements the DataSource interface.
type ArchiveIt struct {
	BaseDataSource
	baseURL string
}

// NewArchiveIt returns an initialized ArchiveIt as a DataSource.
func NewArchiveIt(srv core.AmassService) DataSource {
	a := &ArchiveIt{baseURL: "https://wayback.archive-it.org/all"}

	a.BaseDataSource = *NewBaseDataSource(srv, core.ARCHIVE, "Archive-It")
	return a
}

// Query returns the subdomain names discovered when querying this data source.
func (a *ArchiveIt) Query(domain, sub string) []string {
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
func (a *ArchiveIt) Subdomains() bool {
	return true
}
