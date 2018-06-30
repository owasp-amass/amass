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

type Dogpile struct {
	BaseDataSource
	quantity int
	limit    int
}

func NewDogpile() DataSource {
	d := &Dogpile{
		quantity: 15, // Dogpile returns roughly 15 results per page
		limit:    90,
	}

	d.BaseDataSource = *NewBaseDataSource(SCRAPE, "Dogpile")
	return d
}

func (d *Dogpile) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := d.limit / d.quantity
	for i := 0; i < num; i++ {
		u := d.urlByPageNum(domain, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			d.log(fmt.Sprintf("%s: %v", u, err))
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

func (d *Dogpile) urlByPageNum(domain string, page int) string {
	qsi := strconv.Itoa(d.quantity * page)
	u, _ := url.Parse("http://www.dogpile.com/search/web")

	u.RawQuery = url.Values{"qsi": {qsi}, "q": {domain}}.Encode()
	return u.String()
}
