// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

var (
	commonCrawlIndexes = []string{
		"CC-MAIN-2018-39",
		"CC-MAIN-2018-17",
		"CC-MAIN-2018-05",
		"CC-MAIN-2017-43",
		"CC-MAIN-2017-26",
		"CC-MAIN-2017-17",
		"CC-MAIN-2017-04",
		"CC-MAIN-2016-44",
		"CC-MAIN-2016-26",
		"CC-MAIN-2016-18",
	}
)

// CommonCrawl is data source object type that implements the DataSource interface.
type CommonCrawl struct {
	BaseDataSource
	baseURL string
}

// NewCommonCrawl returns an initialized CommonCrawl as a DataSource.
func NewCommonCrawl(srv core.AmassService) DataSource {
	cc := &CommonCrawl{baseURL: "http://index.commoncrawl.org/"}

	cc.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "Common Crawl")
	return cc
}

// Query returns the subdomain names discovered when querying this data source.
func (cc *CommonCrawl) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	re := utils.SubdomainRegex(domain)
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for _, index := range commonCrawlIndexes {
		cc.Service.SetActive()

		select {
		case <-cc.Service.Quit():
			break loop
		case <-t.C:
			u := cc.getURL(index, domain)
			page, err := utils.GetWebPage(u, nil)
			if err != nil {
				cc.Service.Config().Log.Printf("%s: %v", u, err)
				continue
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

func (cc *CommonCrawl) getURL(index, domain string) string {
	u, _ := url.Parse(cc.baseURL + index + "-index")

	u.RawQuery = url.Values{
		"url":    {"*." + domain},
		"output": {"json"},
	}.Encode()
	return u.String()
}
