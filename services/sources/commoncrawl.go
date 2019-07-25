// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"net/url"
	"strings"
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
		"CC-MAIN-2013-20",
		"CC-MAIN-2013-48",
		"CC-MAIN-2014-10",
		"CC-MAIN-2014-15",
		"CC-MAIN-2014-23",
		"CC-MAIN-2014-35",
		"CC-MAIN-2014-41",
		"CC-MAIN-2014-42",
		"CC-MAIN-2014-49",
		"CC-MAIN-2014-52",
		"CC-MAIN-2015-06",
		"CC-MAIN-2015-11",
		"CC-MAIN-2015-14",
		"CC-MAIN-2015-18",
		"CC-MAIN-2015-22",
		"CC-MAIN-2015-27",
		"CC-MAIN-2015-32",
		"CC-MAIN-2015-35",
		"CC-MAIN-2015-40",
		"CC-MAIN-2015-48",
		"CC-MAIN-2016-07",
		"CC-MAIN-2016-18",
		"CC-MAIN-2016-22",
		"CC-MAIN-2016-26",
		"CC-MAIN-2016-30",
		"CC-MAIN-2016-36",
		"CC-MAIN-2016-40",
		"CC-MAIN-2016-44",
		"CC-MAIN-2016-50",
		"CC-MAIN-2017-04",
		"CC-MAIN-2017-09",
		"CC-MAIN-2017-13",
		"CC-MAIN-2017-17",
		"CC-MAIN-2017-22",
		"CC-MAIN-2017-26",
		"CC-MAIN-2017-30",
		"CC-MAIN-2017-34",
		"CC-MAIN-2017-39",
		"CC-MAIN-2017-43",
		"CC-MAIN-2017-47",
		"CC-MAIN-2017-51",
		"CC-MAIN-2018-05",
		"CC-MAIN-2018-09",
		"CC-MAIN-2018-13",
		"CC-MAIN-2018-17",
		"CC-MAIN-2018-22",
		"CC-MAIN-2018-26",
		"CC-MAIN-2018-30",
		"CC-MAIN-2018-34",
		"CC-MAIN-2018-39",
		"CC-MAIN-2018-43",
		"CC-MAIN-2018-47",
		"CC-MAIN-2018-51",
		"CC-MAIN-2019-04",
		"CC-MAIN-2019-09",
		"CC-MAIN-2019-13",
		"CC-MAIN-2019-18",
		"CC-MAIN-2019-22",
		"CC-MAIN-2019-26",
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
		SourceType: requests.API,
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
	filter := utils.NewStringFilter()
	re := c.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for _, index := range commonCrawlIndexes {
		c.SetActive()

		select {
		case <-c.Quit():
			return
		case <-t.C:
			u := c.getURL(domain, index)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				c.Config().Log.Printf("%s: %s: %v", c.String(), u, err)
				continue
			}

			for _, url := range c.parseJSON(page) {
				if name := re.FindString(url); name != "" && !filter.Duplicate(name) {
					c.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
						Name:   name,
						Domain: domain,
						Tag:    c.SourceType,
						Source: c.String(),
					})
				}
			}
		}
	}
}

func (c *CommonCrawl) parseJSON(page string) []string {
	var urls []string
	filter := utils.NewStringFilter()

	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var m struct {
			URL string `json:"url"`
		}
		err := json.Unmarshal([]byte(line), &m)
		if err != nil {
			continue
		}

		if !filter.Duplicate(m.URL) {
			urls = append(urls, m.URL)
		}
	}
	return urls
}

func (c *CommonCrawl) getURL(domain, index string) string {
	u, _ := url.Parse(c.baseURL + index + "-index")

	u.RawQuery = url.Values{
		"url":      {"*." + domain},
		"output":   {"json"},
		"filter":   {"=status:200"},
		"fl":       {"url,status"},
		"pageSize": {"2000"},
	}.Encode()
	return u.String()
}
