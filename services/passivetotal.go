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

// PassiveTotal is the Service that handles access to the PassiveTotal data source.
type PassiveTotal struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewPassiveTotal returns he object initialized, but not yet started.
func NewPassiveTotal(sys System) *PassiveTotal {
	pt := &PassiveTotal{SourceType: requests.API}

	pt.BaseService = *NewBaseService(pt, "PassiveTotal", sys)
	return pt
}

// Type implements the Service interface.
func (pt *PassiveTotal) Type() string {
	return pt.SourceType
}

// OnStart implements the Service interface.
func (pt *PassiveTotal) OnStart() error {
	pt.BaseService.OnStart()

	pt.API = pt.System().Config().GetAPIKey(pt.String())
	if pt.API == nil || pt.API.Username == "" || pt.API.Key == "" {
		pt.System().Config().Log.Printf("%s: API key data was not provided", pt.String())
	}

	pt.SetRateLimit(5 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (pt *PassiveTotal) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if pt.API == nil || pt.API.Username == "" || pt.API.Key == "" {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	pt.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, pt.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", pt.String(), req.Domain))

	url := pt.restURL(req.Domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, pt.API.Username, pt.API.Key)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", pt.String(), url, err))
		return
	}
	// Extract the subdomain names from the REST API results
	var subs struct {
		Success    bool     `json:"success"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal([]byte(page), &subs); err != nil || !subs.Success {
		return
	}

	for _, s := range subs.Subdomains {
		name := s + "." + req.Domain
		if re.MatchString(name) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: req.Domain,
				Tag:    pt.SourceType,
				Source: pt.String(),
			})
		}
	}
}

func (pt *PassiveTotal) restURL(domain string) string {
	return "https://api.passivetotal.org/v2/enrichment/subdomains?query=" + domain
}
