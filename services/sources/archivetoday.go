// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// ArchiveToday is the Service that handles access to the ArchiveToday data source.
type ArchiveToday struct {
	services.BaseService

	domain     string
	baseURL    string
	SourceType string
	filter     *utils.StringFilter
}

// NewArchiveToday returns he object initialized, but not yet started.
func NewArchiveToday(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *ArchiveToday {
	a := &ArchiveToday{
		domain:     "archive.is",
		baseURL:    "http://archive.is",
		SourceType: requests.ARCHIVE,
		filter:     utils.NewStringFilter(),
	}

	a.BaseService = *services.NewBaseService(a, "ArchiveToday", cfg, bus, pool)
	return a
}

// OnStart implements the Service interface
func (a *ArchiveToday) OnStart() error {
	a.BaseService.OnStart()

	a.Bus().Subscribe(requests.NameResolvedTopic, a.SendDNSRequest)
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

	names, err := crawl(a, a.baseURL, a.domain, sn, domain)
	if err != nil {
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", a.String(), err))
		return
	}

	for _, name := range names {
		a.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}
}
