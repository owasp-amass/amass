// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// UKGovArchive is the Service that handles access to the UKGovArchive data source.
type UKGovArchive struct {
	core.BaseService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewUKGovArchive returns he object initialized, but not yet started.
func NewUKGovArchive(config *core.Config, bus *core.EventBus) *UKGovArchive {
	u := &UKGovArchive{
		baseURL:    "http://webarchive.nationalarchives.gov.uk",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	u.BaseService = *core.NewBaseService(u, "UKGovArchive", config, bus)
	return u
}

// OnStart implements the Service interface
func (u *UKGovArchive) OnStart() error {
	u.BaseService.OnStart()

	u.Bus().Subscribe(core.NameResolvedTopic, u.SendRequest)
	go u.startRootDomains()
	go u.processRequests()
	return nil
}

func (u *UKGovArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range u.Config().Domains() {
		u.executeQuery(domain, domain)
	}
}

func (u *UKGovArchive) processRequests() {
	for {
		select {
		case <-u.Quit():
			return
		case req := <-u.RequestChan():
			u.executeQuery(req.Name, req.Domain)
		}
	}
}

func (u *UKGovArchive) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || u.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(u, u.baseURL, domain, sn)
	if err != nil {
		u.Config().Log.Printf("%s: %v", u.String(), err)
		return
	}

	for _, name := range names {
		u.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    u.SourceType,
			Source: u.String(),
		})
	}
}
