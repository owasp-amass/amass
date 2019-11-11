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

// Shodan is the Service that handles access to the Shodan data source.
type Shodan struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewShodan returns he object initialized, but not yet started.
func NewShodan(sys System) *Shodan {
	s := &Shodan{SourceType: requests.API}

	s.BaseService = *NewBaseService(s, "Shodan", sys)
	return s
}

// Type implements the Service interface.
func (s *Shodan) Type() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *Shodan) OnStart() error {
	s.BaseService.OnStart()

	s.API = s.System().Config().GetAPIKey(s.String())
	if s.API == nil || s.API.Key == "" {
		s.System().Config().Log.Printf("%s: API key data was not provided", s.String())
	}

	s.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (s *Shodan) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil || s.API == nil || s.API.Key == "" {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", s.String(), req.Domain))

	url := s.restURL(req.Domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	}
	// Extract the subdomain names from the REST API results
	var m struct {
		Matches []struct {
			Hostnames []string `json:"hostnames"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	for _, match := range m.Matches {
		for _, host := range match.Hostnames {
			if re.MatchString(host) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   host,
					Domain: req.Domain,
					Tag:    s.SourceType,
					Source: s.String(),
				})
			}
		}
	}
}

func (s *Shodan) restURL(domain string) string {
	return fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=hostname:%s", s.API.Key, domain)
}
