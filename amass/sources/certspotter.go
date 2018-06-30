// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/caffix/amass/amass/internal/utils"
)

type CertSpotter struct {
	BaseDataSource
}

func NewCertSpotter() DataSource {
	c := new(CertSpotter)

	c.BaseDataSource = *NewBaseDataSource(CERT, "CertSpotter")
	return c
}

func (c *CertSpotter) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := c.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		c.log(fmt.Sprintf("%s: %v", url, err))
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

func (c *CertSpotter) getURL(domain string) string {
	format := "https://certspotter.com/api/v0/certs?domain=%s"

	return fmt.Sprintf(format, domain)
}
