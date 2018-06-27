// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"log"
)

const (
	UKGovArchiveSourceString string = "UK Gov Arch"
	ukgovArchiveURL          string = "http://webarchive.nationalarchives.gov.uk"
)

func UKGovArchiveQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	return runArchiveCrawler(ukgovArchiveURL, domain, sub, l)
}
