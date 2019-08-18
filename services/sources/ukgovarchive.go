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
	sf "github.com/OWASP/Amass/stringfilter"
)

// UKGovArchive is the Service that handles access to the UKGovArchive data source.
type UKGovArchive struct {
	services.BaseService

	domain     string
	baseURL    string
	SourceType string
	filter     *sf.StringFilter
}

// NewUKGovArchive returns he object initialized, but not yet started.
func NewUKGovArchive(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *UKGovArchive {
	u := &UKGovArchive{
		domain:     "webarchive.nationalarchives.gov.uk",
		baseURL:    "http://webarchive.nationalarchives.gov.uk",
		SourceType: requests.ARCHIVE,
		filter:     sf.NewStringFilter(),
	}

	u.BaseService = *services.NewBaseService(u, "UKGovArchive", cfg, bus, pool)
	return u
}

// OnStart implements the Service interface
func (u *UKGovArchive) OnStart() error {
	u.BaseService.OnStart()

	u.Bus().Subscribe(requests.NameResolvedTopic, u.SendDNSRequest)
	go u.processRequests()
	return nil
}

func (u *UKGovArchive) processRequests() {
	for {
		select {
		case <-u.Quit():
			return
		case req := <-u.DNSRequestChan():
			if u.Config().IsDomainInScope(req.Name) {
				u.executeQuery(req.Name, req.Domain)
			}
		case <-u.AddrRequestChan():
		case <-u.ASNRequestChan():
		case <-u.WhoisRequestChan():
		}
	}
}

func (u *UKGovArchive) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || u.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(u, u.baseURL, u.domain, sn, domain)
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", u.String(), err))
		return
	}

	for _, name := range names {
		u.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    u.SourceType,
			Source: u.String(),
		})
	}
}
