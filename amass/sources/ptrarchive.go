// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

type PTRArchive struct {
	BaseDataSource
}

func NewPTRArchive(srv core.AmassService) DataSource {
	p := new(PTRArchive)

	p.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "PTRarchive")
	return p
}

func (p *PTRArchive) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := p.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
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
