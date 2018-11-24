// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// FindSubdomains is the AmassService that handles access to the FindSubdomains data source.
type FindSubdomains struct {
	BaseAmassService

	SourceType string
}

// NewFindSubdomains returns he object initialized, but not yet started.
func NewFindSubdomains(e *Enumeration) *FindSubdomains {
	f := &FindSubdomains{SourceType: SCRAPE}

	f.BaseAmassService = *NewBaseAmassService(e, "FindSubdomains", f)
	return f
}

// OnStart implements the AmassService interface
func (f *FindSubdomains) OnStart() error {
	f.BaseAmassService.OnStart()

	go f.startRootDomains()
	go f.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (f *FindSubdomains) OnStop() error {
	f.BaseAmassService.OnStop()
	return nil
}

func (f *FindSubdomains) processRequests() {
	for {
		select {
		case <-f.PauseChan():
			<-f.ResumeChan()
		case <-f.Quit():
			return
		case <-f.RequestChan():
			// This data source just throws away the checked DNS names
			f.SetActive()
		}
	}
}

func (f *FindSubdomains) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range f.Enum().Config.Domains() {
		f.executeQuery(domain)
	}
}

func (f *FindSubdomains) executeQuery(domain string) {
	url := f.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		f.Enum().Log.Printf("%s: %s: %v", f.String(), url, err)
		return
	}

	f.SetActive()
	re := f.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		f.Enum().NewNameEvent(&AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    f.SourceType,
			Source: f.String(),
		})
	}
}

func (f *FindSubdomains) getURL(domain string) string {
	format := "https://findsubdomains.com/subdomains-of/%s"

	return fmt.Sprintf(format, domain)
}
