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
	YahooSourceString string = "Yahoo"
	yahooQuantity     int    = 10
	yahooLimit        int    = 100
)

func YahooQuery(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := yahooLimit / yahooQuantity
	for i := 0; i < num; i++ {
		page := utils.GetWebPage(yahooURLByPageNum(domain, i), nil)
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

func yahooURLByPageNum(domain string, page int) string {
	b := strconv.Itoa(yahooQuantity*page + 1)
	pz := strconv.Itoa(yahooQuantity)

	u, _ := url.Parse("https://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"site:" + domain},
		"b": {b}, "pz": {pz}, "bct": {"0"}, "xargs": {"0"}}.Encode()
	return u.String()
}
