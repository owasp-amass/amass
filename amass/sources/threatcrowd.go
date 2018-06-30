// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/caffix/amass/amass/internal/utils"
)

type ThreatCrowd struct {
	BaseDataSource
}

func NewThreatCrowd() DataSource {
	t := new(ThreatCrowd)

	t.BaseDataSource = *NewBaseDataSource(SCRAPE, "ThreatCrowd")
	return t
}

func (t *ThreatCrowd) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	url := t.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		t.log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (t *ThreatCrowd) getURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}
