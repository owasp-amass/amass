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

// CommonCrawl is the Service that handles access to the CommonCrawl data source.
type CommonCrawl struct {
	core.BaseService

	baseURL    string
	SourceType string
}

// NewCommonCrawl returns he object initialized, but not yet started.
func NewCommonCrawl(config *core.Config, bus *core.EventBus) *CommonCrawl {
	c := &CommonCrawl{
		baseURL:    "http://index.commoncrawl.org/",
		SourceType: core.SCRAPE,
	}

	c.BaseService = *core.NewBaseService(c, "CommonCrawl", config, bus)
	return c
}

// OnStart implements the Service interface
func (c *CommonCrawl) OnStart() error {
	c.BaseService.OnStart()

	go c.startRootDomains()
	return nil
}

func (c *CommonCrawl) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range c.Config().Domains() {
		c.executeQuery(domain)
	}
}

func (c *CommonCrawl) executeQuery(domain string) {
	re := c.Config().DomainRegex(domain)
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for _, index := range commonCrawlIndexes {
		c.SetActive()

		select {
		case <-c.Quit():
			return
		case <-t.C:
			u := c.getURL(index, domain)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				c.Config().Log.Printf("%s: %s: %v", c.String(), u, err)
				continue
			}

			for _, sd := range re.FindAllString(page, -1) {
				c.Bus().Publish(core.NewNameTopic, &core.Request{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    c.SourceType,
					Source: c.String(),
				})
			}
		}
	}
}

func (c *CommonCrawl) getURL(index, domain string) string {
	u, _ := url.Parse(c.baseURL + index + "-index")

	u.RawQuery = url.Values{
		"url":    {"*." + domain},
		"output": {"json"},
	}.Encode()
	return u.String()
}
