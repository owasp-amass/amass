// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// CIRCL is the Service that handles access to the CIRCL data source.
type CIRCL struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewCIRCL returns he object initialized, but not yet started.
func NewCIRCL(config *core.Config, bus *core.EventBus) *CIRCL {
	c := &CIRCL{
		SourceType: core.API,
		RateLimit:  time.Second,
	}

	c.BaseService = *core.NewBaseService(c, "CIRCL", config, bus)
	return c
}

// OnStart implements the Service interface
func (c *CIRCL) OnStart() error {
	c.BaseService.OnStart()

	c.API = c.Config().GetAPIKey(c.String())
	if c.API == nil || c.API.Username == "" || c.API.Password == "" {
		c.Config().Log.Printf("%s: API key data was not provided", c.String())
	}

	go c.processRequests()
	return nil
}

func (c *CIRCL) processRequests() {
	last := time.Now()

	for {
		select {
		case <-c.Quit():
			return
		case req := <-c.RequestChan():
			if c.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < c.RateLimit {
					time.Sleep(c.RateLimit)
				}

				c.executeQuery(req.Domain)
				last = time.Now()
			}
		}
	}
}

func (c *CIRCL) executeQuery(domain string) {
	if c.API == nil || c.API.Username == "" || c.API.Password == "" {
		return
	}

	c.SetActive()
	url := c.restURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, c.API.Username, c.API.Password)
	if err != nil {
		c.Config().Log.Printf("%s: %s: %v", c.String(), url, err)
		return
	}

	c.passiveDNSJSON(page, domain)
}

func (c *CIRCL) restURL(domain string) string {
	return "https://www.circl.lu/pdns/query/" + domain
}

func (c *CIRCL) passiveDNSJSON(page, domain string) {
	var unique []string

	c.SetActive()
	re := c.Config().DomainRegex(domain)
	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j struct {
			Name string `json:"rrname"`
		}
		err := json.Unmarshal([]byte(line), &j)
		if err != nil {
			continue
		}
		if re.MatchString(j.Name) {
			unique = utils.UniqueAppend(unique, j.Name)
		}
	}

	for _, name := range unique {
		c.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   name,
			Domain: domain,
			Tag:    c.SourceType,
			Source: c.String(),
		})
	}
}
