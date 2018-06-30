// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "fmt"

type ArchiveIt struct {
	BaseDataSource
	baseURL string
}

func NewArchiveIt() DataSource {
	a := &ArchiveIt{baseURL: "https://wayback.archive-it.org/all"}

	a.BaseDataSource = *NewBaseDataSource(ARCHIVE, "Archive-It")
	return a
}

func (a *ArchiveIt) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := a.crawl(a.baseURL, domain, sub)
	if err != nil {
		a.log(fmt.Sprintf("%v", err))
	}
	return names
}

func (a *ArchiveIt) Subdomains() bool {
	return true
}
