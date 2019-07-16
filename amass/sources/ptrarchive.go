// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// PTRArchive is the Service that handles access to the Exalead data source.
type PTRArchive struct {
	core.BaseService

	SourceType string
}

// NewPTRArchive returns he object initialized, but not yet started.
func NewPTRArchive(config *core.Config, bus *eventbus.EventBus) *PTRArchive {
	p := &PTRArchive{SourceType: core.SCRAPE}

	p.BaseService = *core.NewBaseService(p, "PTRArchive", config, bus)
	return p
}

// OnStart implements the Service interface
func (p *PTRArchive) OnStart() error {
	p.BaseService.OnStart()

	go p.processRequests()
	return nil
}

func (p *PTRArchive) processRequests() {
	for {
		select {
		case <-p.Quit():
			return
		case req := <-p.DNSRequestChan():
			if p.Config().IsDomainInScope(req.Domain) {
				p.executeQuery(req.Domain)
			}
		case <-p.AddrRequestChan():
		case <-p.ASNRequestChan():
		case <-p.WhoisRequestChan():
		}
	}
}

func (p *PTRArchive) executeQuery(domain string) {
	re := p.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	p.SetActive()
	url := p.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		p.Config().Log.Printf("%s: %s: %v", p.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		name := cleanName(sd)
		if name == "automated_programs_unauthorized."+domain {
			continue
		}

		p.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
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
