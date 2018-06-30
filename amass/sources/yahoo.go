// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

type Yahoo struct {
	BaseDataSource
	quantity int
	limit    int
}

func NewYahoo() DataSource {
	y := &Yahoo{
		quantity: 10,
		limit:    100,
	}

	y.BaseDataSource = *NewBaseDataSource(SCRAPE, "Yahoo")
	return y
}

func (y *Yahoo) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := y.limit / y.quantity
	for i := 0; i < num; i++ {
		u := y.urlByPageNum(domain, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			y.log(fmt.Sprintf("%s: %v", u, err))
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

func (y *Yahoo) urlByPageNum(domain string, page int) string {
	b := strconv.Itoa(y.quantity*page + 1)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("https://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"site:" + domain},
		"b": {b}, "pz": {pz}, "bct": {"0"}, "xargs": {"0"}}.Encode()
	return u.String()
}
