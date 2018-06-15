// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"strconv"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	BingSourceString string = "Bing Scrape"
	bingQuantity     int    = 20
	bingLimit        int    = 200
)

func BingQuery(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := bingLimit / bingQuantity
	for i := 0; i < num; i++ {
		page := utils.GetWebPage(bingURLByPageNum(domain, i), nil)
		if page == "" {
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

func bingURLByPageNum(domain string, page int) string {
	count := strconv.Itoa(bingQuantity)
	first := strconv.Itoa((page * bingQuantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{"q": {"domain:" + domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}
