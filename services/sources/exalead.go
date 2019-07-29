// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// Exalead is the Service that handles access to the Exalead data source.
type Exalead struct {
	services.BaseService

	SourceType string
}

// NewExalead returns he object initialized, but not yet started.
func NewExalead(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Exalead {
	e := &Exalead{SourceType: requests.SCRAPE}

	e.BaseService = *services.NewBaseService(e, "Exalead", cfg, bus, pool)
	return e
}

// OnStart implements the Service interface
func (e *Exalead) OnStart() error {
	e.BaseService.OnStart()

	go e.processRequests()
	return nil
}

func (e *Exalead) processRequests() {
	for {
		select {
		case <-e.Quit():
			return
		case req := <-e.DNSRequestChan():
			if e.Config().IsDomainInScope(req.Domain) {
				e.executeQuery(req.Domain)
			}
		case <-e.AddrRequestChan():
		case <-e.ASNRequestChan():
		case <-e.WhoisRequestChan():
		}
	}
}

func (e *Exalead) executeQuery(domain string) {
	re := e.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	e.SetActive()
	url := e.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		e.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", e.String(), url, err))
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		e.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    e.SourceType,
			Source: e.String(),
		})
	}
}

func (e *Exalead) getURL(domain string) string {
	base := "http://www.exalead.com/search/web/results/"
	format := base + "?q=site:%s+-www?elements_per_page=50"

	return fmt.Sprintf(format, domain)
}
