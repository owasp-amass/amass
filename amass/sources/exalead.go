// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

type Exalead struct {
	BaseDataSource
}

func NewExalead(srv core.AmassService) DataSource {
	e := new(Exalead)

	e.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "Exalead")
	return e
}

func (e *Exalead) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := e.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		e.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	e.Service.SetActive()

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (e *Exalead) getURL(domain string) string {
	base := "http://www.exalead.com/search/web/results/"
	format := base + "?q=site:%s+-www?elements_per_page=50"

	return fmt.Sprintf(format, domain)
}
