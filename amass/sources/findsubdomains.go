// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// FindSubdomains is the AmassService that handles access to the FindSubdomains data source.
type FindSubdomains struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

// NewFindSubdomains requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewFindSubdomains(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *FindSubdomains {
	f := &FindSubdomains{
		Bus:        bus,
		Config:     config,
		SourceType: core.SCRAPE,
	}

	f.BaseAmassService = *core.NewBaseAmassService(e, "FindSubdomains", f)
	return f
}

// OnStart implements the AmassService interface
func (f *FindSubdomains) OnStart() error {
	f.BaseAmassService.OnStart()

	go f.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (f *FindSubdomains) OnStop() error {
	f.BaseAmassService.OnStop()
	return nil
}

func (f *FindSubdomains) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range f.Config.Domains() {
		f.executeQuery(domain)
	}
}

func (f *FindSubdomains) executeQuery(domain string) {
	url := f.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		f.Config.Log.Printf("%s: %s: %v", f.String(), url, err)
		return
	}

	f.SetActive()
	re := f.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &core.AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    f.SourceType,
			Source: f.String(),
		}

		if f.Enum().DupDataSourceName(req) {
			continue
		}
		f.Bus.Publish(core.NEWNAME, req)
	}
}

func (f *FindSubdomains) getURL(domain string) string {
	format := "https://findsubdomains.com/subdomains-of/%s"

	return fmt.Sprintf(format, domain)
}
