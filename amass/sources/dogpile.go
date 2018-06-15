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
	DogpileSourceString string = "Dogpile"
	dogpileQuantity     int    = 15 // Dogpile returns roughly 15 results per page
	dogpileLimit        int    = 90
)

func DogpileQuery(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := dogpileLimit / dogpileQuantity
	for i := 0; i < num; i++ {
		page := utils.GetWebPage(dogpileURLByPageNum(domain, i), nil)
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

func dogpileURLByPageNum(domain string, page int) string {
	qsi := strconv.Itoa(dogpileQuantity * page)
	u, _ := url.Parse("http://www.dogpile.com/search/web")

	u.RawQuery = url.Values{"qsi": {qsi}, "q": {domain}}.Encode()
	return u.String()
}
