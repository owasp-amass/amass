// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

// LoCArchive is data source object type that implements the DataSource interface.
type LoCArchive struct {
	BaseDataSource
	baseURL string
}

// NewLoCArchive returns an initialized LoCArchive as a DataSource.
func NewLoCArchive(srv core.AmassService) DataSource {
	la := &LoCArchive{baseURL: "http://webarchive.loc.gov/all"}

	la.BaseDataSource = *NewBaseDataSource(srv, core.ARCHIVE, "LoC Archive")
	return la
}

// Query returns the subdomain names discovered when querying this data source.
func (la *LoCArchive) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := la.crawl(la.baseURL, domain, sub)
	if err != nil {
		la.Service.Config().Log.Printf("%v", err)
	}
	return names
}

// Subdomains returns true when the data source can query for subdomain names.
func (la *LoCArchive) Subdomains() bool {
	return true
}
