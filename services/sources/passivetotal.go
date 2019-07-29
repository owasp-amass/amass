// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// PassiveTotal is the Service that handles access to the PassiveTotal data source.
type PassiveTotal struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewPassiveTotal returns he object initialized, but not yet started.
func NewPassiveTotal(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *PassiveTotal {
	pt := &PassiveTotal{
		SourceType: requests.API,
		RateLimit:  5 * time.Second,
	}

	pt.BaseService = *services.NewBaseService(pt, "PassiveTotal", cfg, bus, pool)
	return pt
}

// OnStart implements the Service interface
func (pt *PassiveTotal) OnStart() error {
	pt.BaseService.OnStart()

	pt.API = pt.Config().GetAPIKey(pt.String())
	if pt.API == nil || pt.API.Username == "" || pt.API.Key == "" {
		pt.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: API key data was not provided", pt.String()))
	}

	go pt.processRequests()
	return nil
}

func (pt *PassiveTotal) processRequests() {
	last := time.Now()

	for {
		select {
		case <-pt.Quit():
			return
		case req := <-pt.DNSRequestChan():
			if pt.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < pt.RateLimit {
					time.Sleep(pt.RateLimit)
				}
				last = time.Now()
				pt.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-pt.AddrRequestChan():
		case <-pt.ASNRequestChan():
		case <-pt.WhoisRequestChan():
		}
	}
}

func (pt *PassiveTotal) executeQuery(domain string) {
	if pt.API == nil || pt.API.Username == "" || pt.API.Key == "" {
		return
	}

	re := pt.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	pt.SetActive()
	url := pt.restURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, pt.API.Username, pt.API.Key)
	if err != nil {
		pt.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", pt.String(), url, err))
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
		name := s + "." + domain
		if re.MatchString(name) {
			pt.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    pt.SourceType,
				Source: pt.String(),
			})
		}
	}
}

func (pt *PassiveTotal) restURL(domain string) string {
	return "https://api.passivetotal.org/v2/enrichment/subdomains?query=" + domain
}
