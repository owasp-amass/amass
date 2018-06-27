// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"log"
)

const (
	WaybackMachineSourceString string = "Wayback Arc"
	waybackURL                 string = "http://web.archive.org/web"
)

func WaybackMachineQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	return runArchiveCrawler(waybackURL, domain, sub, l)
}
