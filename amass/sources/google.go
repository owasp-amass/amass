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
	GoogleSourceString string = "Google"
	googleQuantity     int    = 10
	googleLimit        int    = 160
)

func GoogleQuery(domain, sub string, l *log.Logger) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := googleLimit / googleQuantity
	for i := 0; i < num; i++ {
		u := googleURLByPageNum(domain, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			l.Printf("Google error: %s: %v", u, err)
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

func googleURLByPageNum(domain string, page int) string {
	start := strconv.Itoa(googleQuantity * page)
	u, _ := url.Parse("https://www.google.com/search")

	u.RawQuery = url.Values{
		"q":      {"site:" + domain},
		"btnG":   {"Search"},
		"hl":     {"en"},
		"biw":    {""},
		"bih":    {""},
		"gbv":    {"1"},
		"start":  {start},
		"filter": {"0"},
	}.Encode()
	return u.String()
}
