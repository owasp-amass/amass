// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// DNSTable is data source object type that implements the DataSource interface.
type DNSTable struct {
	BaseDataSource
}

// NewDNSTable returns an initialized DNSTable as a DataSource.
func NewDNSTable(srv core.AmassService) DataSource {
	h := new(DNSTable)

	h.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "DNSTable")
	return h
}

// Query returns the subdomain names discovered when querying this data source.
func (d *DNSTable) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := d.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	d.Service.SetActive()

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (d *DNSTable) getURL(domain string) string {
	format := "https://dnstable.com/domain/%s"

	return fmt.Sprintf(format, domain)
}
