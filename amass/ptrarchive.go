// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// PTRArchive is the Service that handles access to the Exalead data source.
type PTRArchive struct {
	BaseService

	SourceType string
}

// NewPTRArchive returns he object initialized, but not yet started.
func NewPTRArchive(e *Enumeration) *PTRArchive {
	p := &PTRArchive{SourceType: SCRAPE}

	p.BaseService = *NewBaseService(e, "PTRArchive", p)
	return p
}

// OnStart implements the Service interface
func (p *PTRArchive) OnStart() error {
	p.BaseService.OnStart()

	go p.startRootDomains()
	go p.processRequests()
	return nil
}

func (p *PTRArchive) processRequests() {
	for {
		select {
		case <-p.PauseChan():
			<-p.ResumeChan()
		case <-p.Quit():
			return
		case <-p.RequestChan():
			// This data source just throws away the checked DNS names
			p.SetActive()
		}
	}
}

func (p *PTRArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range p.Enum().Config.Domains() {
		p.executeQuery(domain)
	}
}

func (p *PTRArchive) executeQuery(domain string) {
	url := p.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		p.Enum().Log.Printf("%s: %s: %v", p.String(), url, err)
		return
	}

	p.SetActive()
	re := p.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		name := cleanName(sd)
		if name == "automated_programs_unauthorized."+domain {
			continue
		}

		p.Enum().NewNameEvent(&Request{
			Name:   name,
			Domain: domain,
			Tag:    p.SourceType,
			Source: p.String(),
		})
	}
}

func (p *PTRArchive) getURL(domain string) string {
	format := "http://ptrarchive.com/tools/search3.htm?label=%s&date=ALL"

	return fmt.Sprintf(format, domain)
}
