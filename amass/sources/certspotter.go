// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// CertSpotter is the AmassService that handles access to the CertSpotter data source.
type CertSpotter struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

// NewCertSpotter requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewCertSpotter(bus evbus.Bus, config *core.AmassConfig) *CertSpotter {
	c := &CertSpotter{
		Bus:        bus,
		Config:     config,
		SourceType: core.CERT,
	}

	c.BaseAmassService = *core.NewBaseAmassService("CertSpotter", c)
	return c
}

// OnStart implements the AmassService interface
func (c *CertSpotter) OnStart() error {
	c.BaseAmassService.OnStart()

	go c.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (c *CertSpotter) OnStop() error {
	c.BaseAmassService.OnStop()
	return nil
}

func (c *CertSpotter) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range c.Config.Domains() {
		c.executeQuery(domain)
	}
}

func (c *CertSpotter) executeQuery(domain string) {
	url := c.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		c.Config.Log.Printf("%s: %s: %v", c.String(), url, err)
		return
	}

	c.SetActive()
	re := c.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		n := cleanName(sd)

		if core.DataSourceNameFilter.Duplicate(n) {
			continue
		}

		c.Bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   n,
			Domain: domain,
			Tag:    c.SourceType,
			Source: c.String(),
		})
	}
}

func (c *CertSpotter) getURL(domain string) string {
	format := "https://certspotter.com/api/v0/certs?domain=%s"

	return fmt.Sprintf(format, domain)
}
