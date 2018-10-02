// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

type Arquivo struct {
	BaseDataSource
	baseURL string
}

func NewArquivo(srv core.AmassService) DataSource {
	a := &Arquivo{baseURL: "http://arquivo.pt/wayback"}

	a.BaseDataSource = *NewBaseDataSource(srv, ARCHIVE, "Arquivo Arc")
	return a
}

func (a *Arquivo) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := a.crawl(a.baseURL, domain, sub)
	if err != nil {
		a.Service.Config().Log.Printf("%v", err)
	}
	return names
}

func (a *Arquivo) Subdomains() bool {
	return true
}
