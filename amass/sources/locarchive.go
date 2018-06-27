// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"log"
)

const (
	LoCArchiveSourceString string = "LoC Archive"
	locArchiveURL          string = "http://webarchive.loc.gov/all"
)

func LoCArchiveQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	return runArchiveCrawler(locArchiveURL, domain, sub, l)
}
