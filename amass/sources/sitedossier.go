// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Exalead is the AmassService that handles access to the Exalead data source.
type SiteDossier struct {
	core.BaseAmassService

	SourceType string
}

// NewSiteDossier returns he object initialized, but not yet started.
func NewSiteDossier(e *core.Enumeration) *SiteDossier {
	s := &SiteDossier{SourceType: core.SCRAPE}

	s.BaseAmassService = *core.NewBaseAmassService(e, "SiteDossier", s)
	return s
}

// OnStart implements the AmassService interface
func (s *SiteDossier) OnStart() error {
	s.BaseAmassService.OnStart()

	go s.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (s *SiteDossier) OnStop() error {
	s.BaseAmassService.OnStop()
	return nil
}

func (s *SiteDossier) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range s.Enum().Config.Domains() {
		s.executeQuery(domain)
	}
}

func (s *SiteDossier) executeQuery(domain string) {
	url := s.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		s.Enum().Log.Printf("%s: %s: %v", s.String(), url, err)
		return
	}

	s.SetActive()
	re := s.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &core.AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    s.SourceType,
			Source: s.String(),
		}

		if s.Enum().DupDataSourceName(req) {
			continue
		}
		s.Enum().Bus.Publish(core.NEWNAME, req)
	}
}

func (s *SiteDossier) getURL(domain string) string {
	format := "http://www.sitedossier.com/parentdomain/%s"

	return fmt.Sprintf(format, domain)
}
