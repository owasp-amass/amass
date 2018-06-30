// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "fmt"

type Arquivo struct {
	BaseDataSource
	baseURL string
}

func NewArquivo() DataSource {
	a := &Arquivo{baseURL: "http://arquivo.pt/wayback"}

	a.BaseDataSource = *NewBaseDataSource(ARCHIVE, "Arquivo Arc")
	return a
}

func (a *Arquivo) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := a.crawl(a.baseURL, domain, sub)
	if err != nil {
		a.log(fmt.Sprintf("%v", err))
	}
	return names
}

func (a *Arquivo) Subdomains() bool {
	return true
}
