// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// Censys is the AmassService that handles access to the Censys data source.
type Censys struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

// NewCensys requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewCensys(bus evbus.Bus, config *core.AmassConfig) *Censys {
	c := &Censys{
		Bus:        bus,
		Config:     config,
		SourceType: core.CERT,
	}

	c.BaseAmassService = *core.NewBaseAmassService("Censys", c)
	return c
}

// OnStart implements the AmassService interface
func (c *Censys) OnStart() error {
	c.BaseAmassService.OnStart()

	go c.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (c *Censys) OnStop() error {
	c.BaseAmassService.OnStop()
	return nil
}

func (c *Censys) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range c.Config.Domains() {
		c.executeQuery(domain)
	}
}

func (c *Censys) executeQuery(domain string) {
	var err error
	var url, page string

	if key := c.Config.GetAPIKey(c.String()); key != nil {
		url = c.restURL()

		jsonStr, err := json.Marshal(map[string]string{"query": domain})
		if err != nil {
			return
		}
		body := bytes.NewBuffer(jsonStr)
		headers := map[string]string{"Content-Type": "application/json"}
		page, err = utils.RequestWebPage(url, body, headers, key.UID, key.Secret)
		fmt.Println(page)
	} else {
		url = c.webURL(domain)

		page, err = utils.RequestWebPage(url, nil, nil, "", "")
	}

	if err != nil {
		c.Config.Log.Printf("%s: %s: %v", c.String(), url, err)
		return
	}

	c.SetActive()
	re := c.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if core.DataSourceNameFilter.Duplicate(sd) {
			continue
		}

		c.Bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   sd,
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
