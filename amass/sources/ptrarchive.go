// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	PTRArchiveSourceString string = "PTRarchive"
)

func PTRArchiveQuery(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	page := utils.GetWebPage(ptrArchiveURL(domain), nil)
	if page == "" {
		return unique
	}

	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func ptrArchiveURL(domain string) string {
	format := "http://ptrarchive.com/tools/search2.htm?label=%s&date=ALL"

	return fmt.Sprintf(format, domain)
}
