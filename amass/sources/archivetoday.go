// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

type ArchiveToday struct {
	BaseDataSource
	baseURL string
}

func NewArchiveToday(srv core.AmassService) DataSource {
	a := &ArchiveToday{baseURL: "http://archive.is"}

	a.BaseDataSource = *NewBaseDataSource(srv, ARCHIVE, "Archive Today")
	return a
}

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

func (a *ArchiveToday) Subdomains() bool {
	return true
}
