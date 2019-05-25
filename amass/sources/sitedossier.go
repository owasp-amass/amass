// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// SiteDossier is the Service that handles access to the SiteDossier data source.
type SiteDossier struct {
	core.BaseService

	SourceType string
}

// NewSiteDossier returns he object initialized, but not yet started.
func NewSiteDossier(config *core.Config, bus *core.EventBus) *SiteDossier {
	s := &SiteDossier{SourceType: core.SCRAPE}

	s.BaseService = *core.NewBaseService(s, "SiteDossier", config, bus)
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
		case req := <-s.RequestChan():
			if s.Config().IsDomainInScope(req.Domain) {
				s.executeQuery(req.Domain)
			}
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
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		s.Config().Log.Printf("%s: %s: %v", s.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		s.Bus().Publish(core.NewNameTopic, &core.Request{
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
