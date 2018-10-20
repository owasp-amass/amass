// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Riddler is data source object type that implements the DataSource interface.
type Riddler struct {
	BaseDataSource
}

// NewRiddler returns an initialized Riddler as a DataSource.
func NewRiddler(srv core.AmassService) DataSource {
	r := new(Riddler)

	r.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "Riddler")
	return r
}

// Query returns the subdomain names discovered when querying this data source.
func (r *Riddler) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := r.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		r.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	r.Service.SetActive()

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (r *Riddler) getURL(domain string) string {
	format := "https://riddler.io/search?q=pld:%s"

	return fmt.Sprintf(format, domain)
}
