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

// Wayback is the Service that handles access to the Wayback data source.
type Wayback struct {
	services.BaseService

	SourceType string
	domain     string
	baseURL    string
	filter     *utils.StringFilter
}

// NewWayback returns he object initialized, but not yet started.
func NewWayback(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Wayback {
	w := &Wayback{
		SourceType: requests.ARCHIVE,
		domain:     "web.archive.org",
		baseURL:    "http://web.archive.org/web",
		filter:     utils.NewStringFilter(),
	}

	w.BaseService = *services.NewBaseService(w, "Wayback", cfg, bus, pool)
	return w
}

// OnStart implements the Service interface
func (w *Wayback) OnStart() error {
	w.BaseService.OnStart()

	w.Bus().Subscribe(requests.NameResolvedTopic, w.SendDNSRequest)
	go w.processRequests()
	return nil
}

func (w *Wayback) processRequests() {
	for {
		select {
		case <-w.Quit():
			return
		case req := <-w.DNSRequestChan():
			if w.Config().IsDomainInScope(req.Name) {
				w.executeQuery(req.Name, req.Domain)
			}
		case <-w.AddrRequestChan():
		case <-w.ASNRequestChan():
		case <-w.WhoisRequestChan():
		}
	}
}

func (w *Wayback) executeQuery(sn, domain string) {
	if sn == "" || domain == "" || w.filter.Duplicate(sn) {
		return
	}

	names, err := crawl(w, w.baseURL, w.domain, sn, domain)
	if err != nil {
		w.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", w.String(), err))
		return
	}

	for _, name := range names {
		w.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    w.SourceType,
			Source: w.String(),
		})
	}
}
