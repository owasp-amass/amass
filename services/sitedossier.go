// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// SiteDossier is the Service that handles access to the SiteDossier data source.
type SiteDossier struct {
	BaseService

	SourceType string
}

// NewSiteDossier returns he object initialized, but not yet started.
func NewSiteDossier(sys System) *SiteDossier {
	s := &SiteDossier{SourceType: requests.SCRAPE}

	s.BaseService = *NewBaseService(s, "SiteDossier", sys)
	return s
}

// Type implements the Service interface.
func (s *SiteDossier) Type() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *SiteDossier) OnStart() error {
	s.BaseService.OnStart()

	s.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (s *SiteDossier) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", s.String(), req.Domain))

	url := s.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
			Tag:    s.SourceType,
			Source: s.String(),
		})
	}
}

func (s *SiteDossier) getURL(domain string) string {
	format := "http://www.sitedossier.com/parentdomain/%s"

	return fmt.Sprintf(format, domain)
}
