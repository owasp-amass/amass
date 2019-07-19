// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

var (
	commonCrawlIndexes = []string{
		"CC-MAIN-2019-04",
		"CC-MAIN-2018-47",
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
	services.BaseService

	baseURL    string
	SourceType string
}

// NewCommonCrawl returns he object initialized, but not yet started.
func NewCommonCrawl(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *CommonCrawl {
	c := &CommonCrawl{
		baseURL:    "http://index.commoncrawl.org/",
		SourceType: requests.SCRAPE,
	}

	c.BaseService = *services.NewBaseService(c, "CommonCrawl", cfg, bus, pool)
	return c
}

// OnStart implements the Service interface
func (c *CommonCrawl) OnStart() error {
	c.BaseService.OnStart()

	go c.processRequests()
	return nil
}

func (c *CommonCrawl) processRequests() {
	for {
		select {
		case <-c.Quit():
			return
		case req := <-c.DNSRequestChan():
			if c.Config().IsDomainInScope(req.Domain) {
				c.executeQuery(req.Domain)
			}
		case <-c.AddrRequestChan():
		case <-c.ASNRequestChan():
		case <-c.WhoisRequestChan():
		}
	}
}

func (c *CommonCrawl) executeQuery(domain string) {
	re := c.Config().DomainRegex(domain)
	if re == nil {
		return
	}

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
				c.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
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
