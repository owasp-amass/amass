// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

type Ask struct {
	BaseDataSource
	quantity int
	limit    int
}

func NewAsk() DataSource {
	a := &Ask{
		quantity: 10, // ask.com appears to be hardcoded at 10 results per page
		limit:    100,
	}

	a.BaseDataSource = *NewBaseDataSource(SCRAPE, "Ask Scrape")
	return a
}

func (a *Ask) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := a.limit / a.quantity
	for i := 0; i < num; i++ {
		u := a.urlByPageNum(domain, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			a.log(fmt.Sprintf("%s: %v", u, err))
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
				unique = append(unique, u...)
			}
		}
		time.Sleep(1 * time.Second)
	}
	return unique
}

func (a *Ask) urlByPageNum(domain string, page int) string {
	p := strconv.Itoa(page)
	u, _ := url.Parse("https://www.ask.com/web")

	u.RawQuery = url.Values{"q": {"site:" + domain},
		"o": {"0"}, "l": {"dir"}, "qo": {"pagination"}, "page": {p}}.Encode()
	return u.String()
}
