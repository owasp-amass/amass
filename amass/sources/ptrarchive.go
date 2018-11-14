// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// PTRArchive is data source object type that implements the DataSource interface.
type PTRArchive struct {
	BaseDataSource
}

// NewPTRArchive returns an initialized PTRArchive as a DataSource.
func NewPTRArchive(srv core.AmassService) DataSource {
	p := new(PTRArchive)

	p.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "PTRarchive")
	return p
}

// Query returns the subdomain names discovered when querying this data source.
func (p *PTRArchive) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := p.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		p.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	p.Service.SetActive()

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (p *PTRArchive) getURL(domain string) string {
	format := "http://ptrarchive.com/tools/search3.htm?label=%s&date=ALL"

	return fmt.Sprintf(format, domain)
}
