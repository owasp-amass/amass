// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
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

const commonCrawlIndexListURL = "https://index.commoncrawl.org/collinfo.json"

// CommonCrawl is the Service that handles access to the CommonCrawl data source.
type CommonCrawl struct {
	services.BaseService

	SourceType string
	indexURLs  []string
}

// NewCommonCrawl returns he object initialized, but not yet started.
func NewCommonCrawl(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *CommonCrawl {
	c := &CommonCrawl{SourceType: requests.API}

	c.BaseService = *services.NewBaseService(c, "CommonCrawl", cfg, bus, pool)
	return c
}

// OnStart implements the Service interface
func (c *CommonCrawl) OnStart() error {
	c.BaseService.OnStart()

	// Get all of the index API URLs
	page, err := utils.RequestWebPage(commonCrawlIndexListURL, nil, nil, "", "")
	if err != nil {
		c.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to obtain the index list: %v", c.String(), err),
		)
		return fmt.Errorf("%s: Failed to obtain the index list: %v", c.String(), err)
	}

	type index struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		URL  string `json:"cdx-api"`
	}

	var indexList []index
	if err := json.Unmarshal([]byte(page), &indexList); err != nil {
		c.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to unmarshal the index list: %v", c.String(), err),
		)
		return fmt.Errorf("%s: Failed to unmarshal the index list: %v", c.String(), err)
	}

	for _, i := range indexList {
		c.indexURLs = append(c.indexURLs, i.URL)
	}

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

	for _, index := range c.indexURLs {
		c.SetActive()

		select {
		case <-c.Quit():
			return
		case <-t.C:
			u := c.getURL(domain, index)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				c.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", c.String(), u, err))
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
	u, _ := url.Parse(index)

	u.RawQuery = url.Values{
		"url":      {"*." + domain},
		"output":   {"json"},
		"filter":   {"=status:200"},
		"fl":       {"url,status"},
		"pageSize": {"2000"},
	}.Encode()
	return u.String()
}
