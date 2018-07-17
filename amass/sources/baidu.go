// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/internal/utils"
)

type Baidu struct {
	BaseDataSource
	quantity int
	limit    int
}

func NewBaidu() DataSource {
	b := &Baidu{
		quantity: 20,
		limit:    100,
	}

	b.BaseDataSource = *NewBaseDataSource(SCRAPE, "Baidu")
	return b
}

func (b *Baidu) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := b.limit / b.quantity
	for i := 0; i < num; i++ {
		u := b.urlByPageNum(domain, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			b.log(fmt.Sprintf("%s: %v", u, err))
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

func (b *Baidu) urlByPageNum(domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://www.baidu.com/s")

	u.RawQuery = url.Values{"pn": {pn}, "wd": {domain}, "oq": {domain}}.Encode()
	return u.String()
}
