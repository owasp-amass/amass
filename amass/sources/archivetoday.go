// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// ArchiveToday is the AmassService that handles access to the ArchiveToday data source.
type ArchiveToday struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewArchiveToday requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewArchiveToday(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *ArchiveToday {
	a := &ArchiveToday{
		Bus:        bus,
		Config:     config,
		baseURL:    "http://archive.is",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	a.BaseAmassService = *core.NewBaseAmassService(e, "ArchiveToday", a)
	return a
}

// OnStart implements the AmassService interface
func (a *ArchiveToday) OnStart() error {
	a.BaseAmassService.OnStart()

	a.Bus.SubscribeAsync(core.CHECKED, a.SendRequest, false)
	go a.startRootDomains()
	go a.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (a *ArchiveToday) OnStop() error {
	a.BaseAmassService.OnStop()

	a.Bus.Unsubscribe(core.CHECKED, a.SendRequest)
	return nil
}

func (a *ArchiveToday) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range a.Config.Domains() {
		a.executeQuery(domain, domain)
	}
}

func (a *ArchiveToday) processRequests() {
	for {
		select {
		case <-a.Quit():
			return
		case req := <-a.RequestChan():
			a.executeQuery(req.Name, req.Domain)
		}
	}
}

func (a *ArchiveToday) executeQuery(sn, domain string) {
	if sn == "" || domain == "" {
		return
	}
	if a.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(a, a.baseURL, domain, sn)
	if err != nil {
		a.Config.Log.Printf("%s: %v", a.String(), err)
		return
	}

	for _, name := range names {
		req := &core.AmassRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		}

		if a.Enum().DupDataSourceName(req) {
			continue
		}
		a.Bus.Publish(core.NEWNAME, req)
	}
}
