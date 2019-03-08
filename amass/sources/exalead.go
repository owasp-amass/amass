// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Exalead is the Service that handles access to the Exalead data source.
type Exalead struct {
	core.BaseService

	SourceType string
}

// NewExalead returns he object initialized, but not yet started.
func NewExalead(config *core.Config, bus *core.EventBus) *Exalead {
	e := &Exalead{SourceType: core.SCRAPE}

	e.BaseService = *core.NewBaseService(e, "Exalead", config, bus)
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
		case req := <-e.RequestChan():
			if e.Config().IsDomainInScope(req.Domain) {
				e.executeQuery(req.Domain)
			}
		}
	}
}

func (e *Exalead) executeQuery(domain string) {
	url := e.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		e.Config().Log.Printf("%s: %s: %v", e.String(), url, err)
		return
	}

	e.SetActive()
	re := e.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		e.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
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
