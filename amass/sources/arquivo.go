// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

// Arquivo is data source object type that implements the DataSource interface.
type Arquivo struct {
	BaseDataSource
	baseURL string
}

// NewArquivo returns an initialized Arquivo as a DataSource.
func NewArquivo(srv core.AmassService) DataSource {
	a := &Arquivo{baseURL: "http://arquivo.pt/wayback"}

	a.BaseDataSource = *NewBaseDataSource(srv, core.ARCHIVE, "Arquivo Arc")
	return a
}

// Query returns the subdomain names discovered when querying this data source.
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

// Subdomains returns true when the data source can query for subdomain names.
func (a *Arquivo) Subdomains() bool {
	return true
}
