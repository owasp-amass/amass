// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

type UKGovArchive struct {
	BaseDataSource
	baseURL string
}

func NewUKGovArchive(srv core.AmassService) DataSource {
	u := &UKGovArchive{baseURL: "http://webarchive.nationalarchives.gov.uk"}

	u.BaseDataSource = *NewBaseDataSource(srv, ARCHIVE, "UK Gov Arch")
	return u
}

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

func (u *UKGovArchive) Subdomains() bool {
	return true
}
