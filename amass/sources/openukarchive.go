// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// OpenUKArchive is the Service that handles access to the OpenUKArchive data source.
type OpenUKArchive struct {
	core.BaseService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewOpenUKArchive returns he object initialized, but not yet started.
func NewOpenUKArchive(config *core.Config, bus *core.EventBus) *OpenUKArchive {
	o := &OpenUKArchive{
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

	o.Bus().Subscribe(core.NameResolvedTopic, o.SendRequest)
	go o.startRootDomains()
	go o.processRequests()
	return nil
}

func (o *OpenUKArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range o.Config().Domains() {
		o.executeQuery(domain, domain)
	}
}

func (o *OpenUKArchive) processRequests() {
	for {
		select {
		case <-o.Quit():
			return
		case req := <-o.RequestChan():
			if o.Config().IsDomainInScope(req.Name) {
				o.executeQuery(req.Name, req.Domain)
			}
		}
	}
}

func (o *OpenUKArchive) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || o.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(o, o.baseURL, domain, sn)
	if err != nil {
		o.Config().Log.Printf("%s: %v", o.String(), err)
		return
	}

	for _, name := range names {
		o.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    o.SourceType,
			Source: o.String(),
		})
	}
}
