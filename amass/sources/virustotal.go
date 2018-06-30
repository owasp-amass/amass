// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/caffix/amass/amass/internal/utils"
)

type VirusTotal struct {
	BaseDataSource
}

func NewVirusTotal() DataSource {
	v := new(VirusTotal)

	v.BaseDataSource = *NewBaseDataSource(SCRAPE, "VirusTotal")
	return v
}

func (v *VirusTotal) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	url := v.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		v.log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

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
