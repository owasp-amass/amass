// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// FindSubdomains is the Service that handles access to the FindSubdomains data source.
type FindSubdomains struct {
	core.BaseService

	SourceType string
}

// NewFindSubdomains returns he object initialized, but not yet started.
func NewFindSubdomains(config *core.Config, bus *eventbus.EventBus) *FindSubdomains {
	f := &FindSubdomains{SourceType: core.SCRAPE}

	f.BaseService = *core.NewBaseService(f, "FindSubdomains", config, bus)
	return f
}

// OnStart implements the Service interface
func (f *FindSubdomains) OnStart() error {
	f.BaseService.OnStart()

	go f.processRequests()
	return nil
}

func (f *FindSubdomains) processRequests() {
	for {
		select {
		case <-f.Quit():
			return
		case req := <-f.DNSRequestChan():
			if f.Config().IsDomainInScope(req.Domain) {
				f.executeQuery(req.Domain)
			}
		case <-f.AddrRequestChan():
		case <-f.ASNRequestChan():
		case <-f.WhoisRequestChan():
		}
	}
}

func (f *FindSubdomains) executeQuery(domain string) {
	re := f.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	f.SetActive()
	url := f.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		f.Config().Log.Printf("%s: %s: %v", f.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		f.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
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
