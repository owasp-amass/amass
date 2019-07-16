// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// OpenUKArchive is the Service that handles access to the OpenUKArchive data source.
type OpenUKArchive struct {
	core.BaseService

	domain     string
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewOpenUKArchive returns he object initialized, but not yet started.
func NewOpenUKArchive(config *core.Config, bus *eventbus.EventBus) *OpenUKArchive {
	o := &OpenUKArchive{
		domain:     "webarchive.org.uk",
		baseURL:    "http://www.webarchive.org.uk/wayback/archive",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	o.BaseService = *core.NewBaseService(o, "OpenUKArchive", config, bus)
	return o
}

// OnStart implements the Service interface
func (o *OpenUKArchive) OnStart() error {
	o.BaseService.OnStart()

	o.Bus().Subscribe(core.NameResolvedTopic, o.SendDNSRequest)
	go o.processRequests()
	return nil
}

func (o *OpenUKArchive) processRequests() {
	for {
		select {
		case <-o.Quit():
			return
		case req := <-o.DNSRequestChan():
			if o.Config().IsDomainInScope(req.Name) {
				o.executeQuery(req.Name, req.Domain)
			}
		case <-o.AddrRequestChan():
		case <-o.ASNRequestChan():
		case <-o.WhoisRequestChan():
		}
	}
}

func (o *OpenUKArchive) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || o.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(o, o.baseURL, o.domain, sn, domain)
	if err != nil {
		o.Config().Log.Printf("%s: %v", o.String(), err)
		return
	}

	for _, name := range names {
		o.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    o.SourceType,
			Source: o.String(),
		})
	}
}
