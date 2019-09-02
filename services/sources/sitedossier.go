// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
)

// SiteDossier is the Service that handles access to the SiteDossier data source.
type SiteDossier struct {
	services.BaseService

	SourceType string
}

// NewSiteDossier returns he object initialized, but not yet started.
func NewSiteDossier(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *SiteDossier {
	s := &SiteDossier{SourceType: requests.SCRAPE}

	s.BaseService = *services.NewBaseService(s, "SiteDossier", cfg, bus, pool)
	return s
}

// OnStart implements the Service interface
func (s *SiteDossier) OnStart() error {
	s.BaseService.OnStart()

	go s.processRequests()
	return nil
}

func (s *SiteDossier) processRequests() {
	for {
		select {
		case <-s.Quit():
			return
		case req := <-s.DNSRequestChan():
			if s.Config().IsDomainInScope(req.Domain) {
				s.executeQuery(req.Domain)
			}
		case <-s.AddrRequestChan():
		case <-s.ASNRequestChan():
		case <-s.WhoisRequestChan():
		}
	}
}

func (s *SiteDossier) executeQuery(domain string) {
	re := s.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	s.SetActive()
	url := s.getURL(domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		s.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		s.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    s.SourceType,
			Source: s.String(),
		})
	}
}

func (s *SiteDossier) getURL(domain string) string {
	format := "http://www.sitedossier.com/parentdomain/%s"

	return fmt.Sprintf(format, domain)
}
