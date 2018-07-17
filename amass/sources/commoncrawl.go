// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"time"

	"github.com/OWASP/Amass/amass/internal/utils"
)

var (
	CommonCrawlIndexes = []string{
		"CC-MAIN-2016-18",
		"CC-MAIN-2016-26",
		"CC-MAIN-2016-44",
		"CC-MAIN-2017-04",
		"CC-MAIN-2017-17",
		"CC-MAIN-2017-26",
		"CC-MAIN-2017-43",
		"CC-MAIN-2018-05",
		"CC-MAIN-2018-17",
		"CC-MAIN-2018-26",
	}
)

type CommonCrawl struct {
	BaseDataSource
	baseURL string
}

func NewCommonCrawl() DataSource {
	cc := &CommonCrawl{baseURL: "http://index.commoncrawl.org/"}

	cc.BaseDataSource = *NewBaseDataSource(SCRAPE, "Common Crawl")
	return cc
}

func (cc *CommonCrawl) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	re := utils.SubdomainRegex(domain)
	for _, index := range CommonCrawlIndexes {
		u := cc.getURL(index, domain)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			cc.log(fmt.Sprintf("%s: %v", u, err))
			continue
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

func (cc *CommonCrawl) getURL(index, domain string) string {
	u, _ := url.Parse(cc.baseURL + index + "-index")

	u.RawQuery = url.Values{
		"url":    {"*." + domain},
		"output": {"json"},
	}.Encode()
	return u.String()
}
