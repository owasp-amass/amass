// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
)

// PTRArchive is the Service that handles access to the Exalead data source.
type PTRArchive struct {
	services.BaseService

	SourceType string
}

// NewPTRArchive returns he object initialized, but not yet started.
func NewPTRArchive(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *PTRArchive {
	p := &PTRArchive{SourceType: requests.SCRAPE}

	p.BaseService = *services.NewBaseService(p, "PTRArchive", cfg, bus, pool)
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
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		p.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", p.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		name := cleanName(sd)
		if name == "automated_programs_unauthorized."+domain {
			continue
		}

		p.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
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
