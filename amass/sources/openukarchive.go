// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// OpenUKArchive is the AmassService that handles access to the OpenUKArchive data source.
type OpenUKArchive struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewOpenUKArchive requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewOpenUKArchive(bus evbus.Bus, config *core.AmassConfig) *OpenUKArchive {
	o := &OpenUKArchive{
		Bus:        bus,
		Config:     config,
		baseURL:    "http://www.webarchive.org.uk/wayback/archive",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	o.BaseAmassService = *core.NewBaseAmassService("OpenUKArchive", o)
	return o
}

// OnStart implements the AmassService interface
func (o *OpenUKArchive) OnStart() error {
	o.BaseAmassService.OnStart()

	o.Bus.SubscribeAsync(core.CHECKED, o.SendRequest, false)
	go o.startRootDomains()
	go o.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (o *OpenUKArchive) OnStop() error {
	o.BaseAmassService.OnStop()

	o.Bus.Unsubscribe(core.CHECKED, o.SendRequest)
	return nil
}

func (o *OpenUKArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range o.Config.Domains() {
		o.executeQuery(domain, domain)
	}
}

func (o *OpenUKArchive) processRequests() {
	for {
		select {
		case <-o.Quit():
			return
		case req := <-o.RequestChan():
			o.executeQuery(req.Name, req.Domain)
		}
	}
}

func (o *OpenUKArchive) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if o.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(o, o.baseURL, domain, sn)
	if err != nil {
		o.Config.Log.Printf("%s: %v", o.String(), err)
		return
	}

	for _, name := range names {
		n := cleanName(name)

		if core.DataSourceNameFilter.Duplicate(n) {
			continue
		}

		o.Bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   n,
			Domain: domain,
			Tag:    o.SourceType,
			Source: o.String(),
		})
	}
}
