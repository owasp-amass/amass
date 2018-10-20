// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

// WaybackMachine is data source object type that implements the DataSource interface.
type WaybackMachine struct {
	BaseDataSource
	baseURL string
}

// NewWaybackMachine returns an initialized WaybackMachine as a DataSource.
func NewWaybackMachine(srv core.AmassService) DataSource {
	w := &WaybackMachine{baseURL: "http://web.archive.org/web"}

	w.BaseDataSource = *NewBaseDataSource(srv, core.ARCHIVE, "Wayback Arc")
	return w
}

// Query returns the subdomain names discovered when querying this data source.
func (w *WaybackMachine) Query(domain, sub string) []string {
	if sub == "" {
		return []string{}
	}

	names, err := w.crawl(w.baseURL, domain, sub)
	if err != nil {
		w.Service.Config().Log.Printf("%v", err)
	}
	return names
}

// Subdomains returns true when the data source can query for subdomain names.
func (w *WaybackMachine) Subdomains() bool {
	return true
}
