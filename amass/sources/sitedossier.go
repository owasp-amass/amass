// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

type SiteDossier struct {
	BaseDataSource
}

func NewSiteDossier() DataSource {
	s := new(SiteDossier)

	s.BaseDataSource = *NewBaseDataSource(SCRAPE, "SiteDossier")
	return s
}

func (s *SiteDossier) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	url := s.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		s.log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (s *SiteDossier) getURL(domain string) string {
	format := "http://www.sitedossier.com/parentdomain/%s"

	return fmt.Sprintf(format, domain)
}
