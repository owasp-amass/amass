// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"log"
)

const (
	ArchiveItSourceString string = "Archive-It"
	archiveItURL          string = "https://wayback.archive-it.org/all"
)

func ArchiveItQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	return runArchiveCrawler(archiveItURL, domain, sub, l)
}
