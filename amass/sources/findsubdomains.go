// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// FindSubdomains is data source object type that implements the DataSource interface.
type FindSubdomains struct {
	BaseDataSource
}

// NewFindSubdomains returns an initialized FindSubdomains as a DataSource.
func NewFindSubdomains(srv core.AmassService) DataSource {
	f := new(FindSubdomains)

	f.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "FindSubDomains")
	return f
}

// Query returns the subdomain names discovered when querying this data source.
func (f *FindSubdomains) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := f.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		f.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	f.Service.SetActive()

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
