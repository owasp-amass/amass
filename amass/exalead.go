// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// Exalead is the AmassService that handles access to the Exalead data source.
type Exalead struct {
	BaseAmassService

	SourceType string
}

// NewExalead returns he object initialized, but not yet started.
func NewExalead(enum *Enumeration) *Exalead {
	e := &Exalead{SourceType: SCRAPE}

	e.BaseAmassService = *NewBaseAmassService(enum, "Exalead", e)
	return e
}

// OnStart implements the AmassService interface
func (e *Exalead) OnStart() error {
	e.BaseAmassService.OnStart()

	go e.startRootDomains()
	go e.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (e *Exalead) OnStop() error {
	e.BaseAmassService.OnStop()
	return nil
}

func (e *Exalead) processRequests() {
	for {
		select {
		case <-e.PauseChan():
			<-e.ResumeChan()
		case <-e.Quit():
			return
		case <-e.RequestChan():
			// This data source just throws away the checked DNS names
			e.SetActive()
		}
	}
}

func (e *Exalead) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range e.Enum().Config.Domains() {
		e.executeQuery(domain)
	}
}

func (e *Exalead) executeQuery(domain string) {
	url := e.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		e.Enum().Log.Printf("%s: %s: %v", e.String(), url, err)
		return
	}

	e.SetActive()
	re := e.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		e.Enum().NewNameEvent(&AmassRequest{
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
