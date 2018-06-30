// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "fmt"

type ArchiveToday struct {
	BaseDataSource
	baseURL string
}

func NewArchiveToday() DataSource {
	a := &ArchiveToday{baseURL: "http://archive.is"}

	a.BaseDataSource = *NewBaseDataSource(ARCHIVE, "Archive Today")
	return a
}

func (a *ArchiveToday) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := a.crawl(a.baseURL, domain, sub)
	if err != nil {
		a.log(fmt.Sprintf("%v", err))
	}
	return names
}

func (a *ArchiveToday) Subdomains() bool {
	return true
}
