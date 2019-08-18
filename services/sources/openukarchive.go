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

// OpenUKArchive is the Service that handles access to the OpenUKArchive data source.
type OpenUKArchive struct {
	services.BaseService

	domain     string
	baseURL    string
	SourceType string
	filter     *sf.StringFilter
}

// NewOpenUKArchive returns he object initialized, but not yet started.
func NewOpenUKArchive(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *OpenUKArchive {
	o := &OpenUKArchive{
		domain:     "webarchive.org.uk",
		baseURL:    "http://www.webarchive.org.uk/wayback/archive",
		SourceType: requests.ARCHIVE,
		filter:     sf.NewStringFilter(),
	}

	o.BaseService = *services.NewBaseService(o, "OpenUKArchive", cfg, bus, pool)
	return o
}

// OnStart implements the Service interface
func (o *OpenUKArchive) OnStart() error {
	o.BaseService.OnStart()

	o.Bus().Subscribe(requests.NameResolvedTopic, o.SendDNSRequest)
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
		o.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", o.String(), err))
		return
	}

	for _, name := range names {
		o.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    o.SourceType,
			Source: o.String(),
		})
	}
}
