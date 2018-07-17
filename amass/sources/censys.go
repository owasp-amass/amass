// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/internal/utils"
)

type Censys struct {
	BaseDataSource
}

func NewCensys() DataSource {
	c := new(Censys)

	c.BaseDataSource = *NewBaseDataSource(SCRAPE, "Censys")
	return c
}

func (c *Censys) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	url := c.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		c.log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (c *Censys) getURL(domain string) string {
	format := "https://www.censys.io/domain/%s/table"

	return fmt.Sprintf(format, domain)
}
