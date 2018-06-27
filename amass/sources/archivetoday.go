// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"log"
)

const (
	ArchiveTodaySourceString string = "Archive Today"
	archiveTodayURL          string = "http://archive.is"
)

func ArchiveTodayQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	return runArchiveCrawler(archiveTodayURL, domain, sub, l)
}
