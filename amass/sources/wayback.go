// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import "github.com/OWASP/Amass/amass/core"

type WaybackMachine struct {
	BaseDataSource
	baseURL string
}

func NewWaybackMachine(srv core.AmassService) DataSource {
	w := &WaybackMachine{baseURL: "http://web.archive.org/web"}

	w.BaseDataSource = *NewBaseDataSource(srv, ARCHIVE, "Wayback Arc")
	return w
}

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

func (w *WaybackMachine) Subdomains() bool {
	return true
}
