// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/internal/utils"
)

type Netcraft struct {
	BaseDataSource
}

func NewNetcraft() DataSource {
	d := new(Netcraft)

	d.BaseDataSource = *NewBaseDataSource(SCRAPE, "Netcraft")
	return d
}

func (n *Netcraft) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := n.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		n.log(fmt.Sprintf("%s, %v", url, err))
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

func (n *Netcraft) getURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}
