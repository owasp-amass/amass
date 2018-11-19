// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// UKGovArchive is the AmassService that handles access to the UKGovArchive data source.
type UKGovArchive struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewUKGovArchive requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewUKGovArchive(bus evbus.Bus, config *core.AmassConfig) *UKGovArchive {
	u := &UKGovArchive{
		Bus:        bus,
		Config:     config,
		baseURL:    "http://webarchive.nationalarchives.gov.uk",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	u.BaseAmassService = *core.NewBaseAmassService("UKGovArchive", u)
	return u
}

// OnStart implements the AmassService interface
func (u *UKGovArchive) OnStart() error {
	u.BaseAmassService.OnStart()

	u.Bus.SubscribeAsync(core.CHECKED, u.SendRequest, false)
	go u.startRootDomains()
	go u.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (u *UKGovArchive) OnStop() error {
	u.BaseAmassService.OnStop()

	u.Bus.Unsubscribe(core.CHECKED, u.SendRequest)
	return nil
}

func (u *UKGovArchive) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range u.Config.Domains() {
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
	if sn == "" || domain == "" {
		return
	}
	if u.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(u, u.baseURL, domain, sn)
	if err != nil {
		u.Config.Log.Printf("%s: %v", u.String(), err)
		return
	}

	for _, n := range names {
		go func(name string) {
			u.Config.MaxFlow.Acquire(1)
			u.Bus.Publish(core.NEWNAME, &core.AmassRequest{
				Name:   cleanName(name),
				Domain: domain,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}(n)
	}
}
