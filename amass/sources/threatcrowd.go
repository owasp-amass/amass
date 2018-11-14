// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// ThreatCrowd is data source object type that implements the DataSource interface.
type ThreatCrowd struct {
	BaseDataSource
}

// NewThreatCrowd returns an initialized ThreatCrowd as a DataSource.
func NewThreatCrowd(srv core.AmassService) DataSource {
	t := new(ThreatCrowd)

	t.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "ThreatCrowd")
	return t
}

// Query returns the subdomain names discovered when querying this data source.
func (t *ThreatCrowd) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := t.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		t.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}

	t.Service.SetActive()
	re := t.Service.Config().DomainRegex(domain)
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
