// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// CertSpotter is the Service that handles access to the CertSpotter data source.
type CertSpotter struct {
	core.BaseService

	SourceType string
}

// NewCertSpotter returns he object initialized, but not yet started.
func NewCertSpotter(config *core.Config, bus *core.EventBus) *CertSpotter {
	c := &CertSpotter{SourceType: core.CERT}

	c.BaseService = *core.NewBaseService(c, "CertSpotter", config, bus)
	return c
}

// OnStart implements the Service interface
func (c *CertSpotter) OnStart() error {
	c.BaseService.OnStart()

	go c.processRequests()
	return nil
}

func (c *CertSpotter) processRequests() {
	for {
		select {
		case <-c.Quit():
			return
		case req := <-c.RequestChan():
			if c.Config().IsDomainInScope(req.Domain) {
				c.executeQuery(req.Domain)
			}
		}
	}
}

func (c *CertSpotter) executeQuery(domain string) {
	url := c.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		c.Config().Log.Printf("%s: %s: %v", c.String(), url, err)
		return
	}

	c.SetActive()
	re := c.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		c.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
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
