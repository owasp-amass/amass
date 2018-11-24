// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// CertSpotter is the AmassService that handles access to the CertSpotter data source.
type CertSpotter struct {
	BaseAmassService

	SourceType string
}

// NewCertSpotter returns he object initialized, but not yet started.
func NewCertSpotter(e *Enumeration) *CertSpotter {
	c := &CertSpotter{SourceType: CERT}

	c.BaseAmassService = *NewBaseAmassService(e, "CertSpotter", c)
	return c
}

// OnStart implements the AmassService interface
func (c *CertSpotter) OnStart() error {
	c.BaseAmassService.OnStart()

	go c.startRootDomains()
	go c.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (c *CertSpotter) OnStop() error {
	c.BaseAmassService.OnStop()
	return nil
}

func (c *CertSpotter) processRequests() {
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

func (c *CertSpotter) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range c.Enum().Config.Domains() {
		c.executeQuery(domain)
	}
}

func (c *CertSpotter) executeQuery(domain string) {
	url := c.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		c.Enum().Log.Printf("%s: %s: %v", c.String(), url, err)
		return
	}

	c.SetActive()
	re := c.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		c.Enum().NewNameEvent(&AmassRequest{
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
