// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"net/url"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// CertDB is the AmassService that handles access to the CertDB data source.
type CertDB struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
	filter     *utils.StringFilter
}

// NewCertDB requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewCertDB(bus evbus.Bus, config *core.AmassConfig) *CertDB {
	c := &CertDB{
		Bus:        bus,
		Config:     config,
		SourceType: core.CERT,
		filter:     utils.NewStringFilter(),
	}

	c.BaseAmassService = *core.NewBaseAmassService("CertDB", c)
	return c
}

// OnStart implements the AmassService interface
func (c *CertDB) OnStart() error {
	c.BaseAmassService.OnStart()

	go c.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (c *CertDB) OnStop() error {
	c.BaseAmassService.OnStop()
	return nil
}

func (c *CertDB) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range c.Config.Domains() {
		c.executeQuery(domain)
	}
}

func (c *CertDB) executeQuery(domain string) {
	u := c.getURL(domain)
	page, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		c.Config.Log.Printf("%s: %s: %v", c.String(), u, err)
		return
	}

	var names []string
	if err := json.Unmarshal([]byte(page), &names); err != nil {
		c.Config.Log.Printf("%s: Failed to unmarshal JSON: %v", c.String(), err)
		return
	}

	c.SetActive()
	re := c.Config.DomainRegex(domain)
	for _, name := range names {
		n := re.FindString(name)
		if n == "" || c.filter.Duplicate(n) {
			continue
		}
		go func(name string) {
			c.Config.MaxFlow.Acquire(1)
			c.Bus.Publish(core.NEWNAME, &core.AmassRequest{
				Name:   name,
				Domain: domain,
				Tag:    c.SourceType,
				Source: c.String(),
			})
		}(n)
	}
}

func (c *CertDB) getURL(domain string) string {
	u, _ := url.Parse("https://certdb.com/api")

	u.RawQuery = url.Values{
		"q":             {domain},
		"response_type": {"3"},
	}.Encode()
	return u.String()
}
