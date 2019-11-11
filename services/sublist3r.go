// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// Sublist3rAPI is the Service that handles access to the Sublist3r API data source.
type Sublist3rAPI struct {
	BaseService

	SourceType string
}

// NewSublist3rAPI returns he object initialized, but not yet started.
func NewSublist3rAPI(sys System) *Sublist3rAPI {
	s := &Sublist3rAPI{SourceType: requests.API}

	s.BaseService = *NewBaseService(s, "Sublist3rAPI", sys)
	return s
}

// Type implements the Service interface.
func (s *Sublist3rAPI) Type() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *Sublist3rAPI) OnStart() error {
	s.BaseService.OnStart()

	s.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (s *Sublist3rAPI) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", s.String(), req.Domain))

	url := s.restURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	}

	// Extract the subdomain names from the REST API results
	var subs []string
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	} else if len(subs) == 0 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", s.String(), url),
		)
		return
	}

	for _, sub := range subs {
		if cfg.IsDomainInScope(sub) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   sub,
				Domain: req.Domain,
				Tag:    s.SourceType,
				Source: s.String(),
			})
		}
	}
}

func (s *Sublist3rAPI) restURL(domain string) string {
	return fmt.Sprintf("https://api.sublist3r.com/search.php?domain=%s", domain)
}
