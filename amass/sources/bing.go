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

type Bing struct {
	BaseDataSource
	quantity int
	limit    int
}

func NewBing(srv core.AmassService) DataSource {
	b := &Bing{
		quantity: 20,
		limit:    200,
	}

	b.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "Bing Scrape")
	return b
}

func (b *Bing) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := b.limit / b.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for i := 0; i < num; i++ {
		b.Service.SetActive()

		select {
		case <-b.Service.Quit():
			break loop
		case <-t.C:
			u := b.urlByPageNum(domain, i)
			page, err := utils.GetWebPage(u, nil)
			if err != nil {
				b.Service.Config().Log.Printf("%s: %v", u, err)
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

func (b *Bing) urlByPageNum(domain string, page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{"q": {"domain:" + domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}
