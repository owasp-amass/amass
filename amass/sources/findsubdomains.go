// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/caffix/amass/amass/internal/utils"
)

type FindSubdomains struct {
	BaseDataSource
}

func NewFindSubdomains() DataSource {
	f := new(FindSubdomains)

	f.BaseDataSource = *NewBaseDataSource(SCRAPE, "FindSubDmns")
	return f
}

func (f *FindSubdomains) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := f.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		f.Log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (f *FindSubdomains) getURL(domain string) string {
	format := "https://findsubdomains.com/subdomains-of/%s"

	return fmt.Sprintf(format, domain)
}
