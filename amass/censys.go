// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Censys is the Service that handles access to the Censys data source.
type Censys struct {
	BaseService

	API        *APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewCensys returns he object initialized, but not yet started.
func NewCensys(e *Enumeration) *Censys {
	c := &Censys{
		SourceType: CERT,
		RateLimit:  3 * time.Second,
	}

	c.BaseService = *NewBaseService(e, "Censys", c)
	return c
}

// OnStart implements the Service interface
func (c *Censys) OnStart() error {
	c.BaseService.OnStart()

	c.API = c.Enum().Config.GetAPIKey(c.String())
	if c.API == nil || c.API.Key == "" || c.API.Secret == "" {
		c.Enum().Log.Printf("%s: API key data was not provided", c.String())
	}
	go c.startRootDomains()
	go c.processRequests()
	return nil
}

func (c *Censys) processRequests() {
	for {
		select {
		case <-c.PauseChan():
			<-c.ResumeChan()
		case <-c.Quit():
			return
		case <-c.RequestChan():
			// This data source just throws away the checked DNS names
			c.SetActive()
		}
	}
}

func (c *Censys) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range c.Enum().Config.Domains() {
		c.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(c.RateLimit)
	}
}

func (c *Censys) executeQuery(domain string) {
	var err error
	var url, page string

	if c.API != nil && c.API.Key != "" && c.API.Secret != "" {
		jsonStr, err := json.Marshal(map[string]string{"query": domain})
		if err != nil {
			return
		}

		url = c.restURL()
		body := bytes.NewBuffer(jsonStr)
		headers := map[string]string{"Content-Type": "application/json"}
		page, err = utils.RequestWebPage(url, body, headers, c.API.Key, c.API.Secret)
	} else {
		url = c.webURL(domain)

		page, err = utils.RequestWebPage(url, nil, nil, "", "")
	}
	if err != nil {
		c.Enum().Log.Printf("%s: %s: %v", c.String(), url, err)
		return
	}

	c.SetActive()
	re := c.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		c.Enum().NewNameEvent(&Request{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    c.SourceType,
			Source: c.String(),
		})
	}
}

func (c *Censys) webURL(domain string) string {
	return fmt.Sprintf("https://www.censys.io/domain/%s/table", domain)
}

func (c *Censys) restURL() string {
	return "https://www.censys.io/api/v1/search/certificates"
}
