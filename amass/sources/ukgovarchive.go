// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

// UKGovArchive is data source object type that implements the DataSource interface.
type UKGovArchive struct {
	BaseDataSource
	baseURL string
}

// NewUKGovArchive returns an initialized UKGovArchive as a DataSource.
func NewUKGovArchive(srv core.AmassService) DataSource {
	u := &UKGovArchive{baseURL: "http://webarchive.nationalarchives.gov.uk"}

	u.BaseDataSource = *NewBaseDataSource(srv, core.ARCHIVE, "UK Gov Arch")
	return u
}

// Query returns the subdomain names discovered when querying this data source.
func (u *UKGovArchive) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := u.crawl(u.baseURL, domain, sub)
	if err != nil {
		u.Service.Config().Log.Printf("%v", err)
	}
	return names
}

// Subdomains returns true when the data source can query for subdomain names.
func (u *UKGovArchive) Subdomains() bool {
	return true
}
