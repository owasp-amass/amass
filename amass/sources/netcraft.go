// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Netcraft is data source object type that implements the DataSource interface.
type Netcraft struct {
	BaseDataSource
}

// NewNetcraft returns an initialized Netcraft as a DataSource.
func NewNetcraft(srv core.AmassService) DataSource {
	d := new(Netcraft)

	d.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "Netcraft")
	return d
}

// Query returns the subdomain names discovered when querying this data source.
func (n *Netcraft) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := n.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		n.Service.Config().Log.Printf("%s, %v", url, err)
		return unique
	}
	n.Service.SetActive()

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
