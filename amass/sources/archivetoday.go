// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// ArchiveToday is the Service that handles access to the ArchiveToday data source.
type ArchiveToday struct {
	core.BaseService

	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewArchiveToday returns he object initialized, but not yet started.
func NewArchiveToday(config *core.Config, bus *core.EventBus) *ArchiveToday {
	a := &ArchiveToday{
		baseURL:    "http://archive.is",
		SourceType: core.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	a.BaseService = *core.NewBaseService(a, "ArchiveToday", config, bus)
	return a
}

// OnStart implements the Service interface
func (a *ArchiveToday) OnStart() error {
	a.BaseService.OnStart()

	a.Bus().Subscribe(core.NameResolvedTopic, a.SendDNSRequest)
	go a.processRequests()
	return nil
}

func (a *ArchiveToday) processRequests() {
	for {
		select {
		case <-a.Quit():
			return
		case req := <-a.DNSRequestChan():
			if a.Config().IsDomainInScope(req.Name) {
				a.executeQuery(req.Name, req.Domain)
			}
		case <-a.AddrRequestChan():
		case <-a.ASNRequestChan():
		case <-a.WhoisRequestChan():
		}
	}
}

func (a *ArchiveToday) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || a.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(a, a.baseURL, domain, sn)
	if err != nil {
		a.Config().Log.Printf("%s: %v", a.String(), err)
		return
	}

	for _, name := range names {
		a.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}
}
