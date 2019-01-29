// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// FindSubdomains is the Service that handles access to the FindSubdomains data source.
type FindSubdomains struct {
	core.BaseService

	SourceType string
}

// NewFindSubdomains returns he object initialized, but not yet started.
func NewFindSubdomains(config *core.Config, bus *core.EventBus) *FindSubdomains {
	f := &FindSubdomains{SourceType: core.SCRAPE}

	f.BaseService = *core.NewBaseService(f, "FindSubdomains", config, bus)
	return f
}

// OnStart implements the Service interface
func (f *FindSubdomains) OnStart() error {
	f.BaseService.OnStart()

	go f.startRootDomains()
	return nil
}

func (f *FindSubdomains) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range f.Config().Domains() {
		f.executeQuery(domain)
	}
}

func (f *FindSubdomains) executeQuery(domain string) {
	url := f.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		f.Config().Log.Printf("%s: %s: %v", f.String(), url, err)
		return
	}

	f.SetActive()
	re := f.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		f.Bus().Publish(core.NewNameTopic, &core.Request{
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
