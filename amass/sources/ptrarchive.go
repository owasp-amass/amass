// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// PTRArchive is the Service that handles access to the Exalead data source.
type PTRArchive struct {
	core.BaseService

	SourceType string
}

// NewPTRArchive returns he object initialized, but not yet started.
func NewPTRArchive(config *core.Config, bus *core.EventBus) *PTRArchive {
	p := &PTRArchive{SourceType: core.SCRAPE}

	p.BaseService = *core.NewBaseService(p, "PTRArchive", config, bus)
	return p
}

// OnStart implements the Service interface
func (p *PTRArchive) OnStart() error {
	p.BaseService.OnStart()

	go p.startRootDomains()
	return nil
}

func (p *PTRArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range p.Config().Domains() {
		p.executeQuery(domain)
	}
}

func (p *PTRArchive) executeQuery(domain string) {
	url := p.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		p.Config().Log.Printf("%s: %s: %v", p.String(), url, err)
		return
	}

	p.SetActive()
	re := p.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		name := cleanName(sd)
		if name == "automated_programs_unauthorized."+domain {
			continue
		}

		p.Bus().Publish(core.NewNameTopic, &core.Request{
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
