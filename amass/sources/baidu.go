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
	BaiduSourceString string = "Baidu"
	baiduQuantity     int    = 20
	baiduLimit        int    = 100
)

func BaiduQuery(domain, sub string, l *log.Logger) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	num := baiduLimit / baiduQuantity
	for i := 0; i < num; i++ {
		u := baiduURLByPageNum(domain, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			l.Printf("Baidu error: %s: %v", u, err)
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

func baiduURLByPageNum(domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://www.baidu.com/s")

	u.RawQuery = url.Values{"pn": {pn}, "wd": {domain}, "oq": {domain}}.Encode()
	return u.String()
}
