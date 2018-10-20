// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// VirusTotal is data source object type that implements the DataSource interface.
type VirusTotal struct {
	BaseDataSource
}

// NewVirusTotal returns an initialized VirusTotal as a DataSource.
func NewVirusTotal(srv core.AmassService) DataSource {
	v := new(VirusTotal)

	v.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "VirusTotal")
	return v
}

// Query returns the subdomain names discovered when querying this data source.
func (v *VirusTotal) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	url := v.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		v.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	v.Service.SetActive()

	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (v *VirusTotal) getURL(domain string) string {
	format := "https://www.virustotal.com/en/domain/%s/information/"

	return fmt.Sprintf(format, domain)
}
