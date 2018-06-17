// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"log"
	"net/url"
	"strconv"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	AskSourceString string = "Ask Scrape"
	askQuantity     int    = 10 // ask.com appears to be hardcoded at 10 results per page
	askLimit        int    = 100
)

func AskQuery(domain, sub string, l *log.Logger) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := askLimit / askQuantity
	for i := 0; i < num; i++ {
		u := askURLByPageNum(domain, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			l.Printf("Ask error: %s: %v", u, err)
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

func askURLByPageNum(domain string, page int) string {
	p := strconv.Itoa(page)
	u, _ := url.Parse("https://www.ask.com/web")

	u.RawQuery = url.Values{"q": {"site:" + domain},
		"o": {"0"}, "l": {"dir"}, "qo": {"pagination"}, "page": {p}}.Encode()
	return u.String()
}
