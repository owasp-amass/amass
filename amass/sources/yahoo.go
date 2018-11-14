// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Yahoo is data source object type that implements the DataSource interface.
type Yahoo struct {
	BaseDataSource
	quantity int
	limit    int
}

// NewYahoo returns an initialized Yahoo as a DataSource.
func NewYahoo(srv core.AmassService) DataSource {
	y := &Yahoo{
		quantity: 10,
		limit:    100,
	}

	y.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "Yahoo")
	return y
}

// Query returns the subdomain names discovered when querying this data source.
func (y *Yahoo) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := y.limit / y.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for i := 0; i < num; i++ {
		y.Service.SetActive()

		select {
		case <-y.Service.Quit():
			break loop
		case <-t.C:
			u := y.urlByPageNum(domain, i)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				y.Service.Config().Log.Printf("%s: %v", u, err)
				break
			}

			for _, sd := range re.FindAllString(page, -1) {
				if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
					unique = append(unique, u...)
				}
			}
		}
	}
	return unique
}

func (y *Yahoo) urlByPageNum(domain string, page int) string {
	b := strconv.Itoa(y.quantity*page + 1)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("https://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"site:" + domain},
		"b": {b}, "pz": {pz}, "bct": {"0"}, "xargs": {"0"}}.Encode()
	return u.String()
}
