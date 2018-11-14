// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// SiteDossier is data source object type that implements the DataSource interface.
type SiteDossier struct {
	BaseDataSource
}

// NewSiteDossier returns an initialized SiteDossier as a DataSource.
func NewSiteDossier(srv core.AmassService) DataSource {
	s := new(SiteDossier)

	s.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "SiteDossier")
	return s
}

// Query returns the subdomain names discovered when querying this data source.
func (s *SiteDossier) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	url := s.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		s.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	s.Service.SetActive()

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
