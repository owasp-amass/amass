// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// PassiveTotal is the Service that handles access to the PassiveTotal data source.
type PassiveTotal struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewPassiveTotal returns he object initialized, but not yet started.
func NewPassiveTotal(config *core.Config, bus *core.EventBus) *PassiveTotal {
	pt := &PassiveTotal{
		SourceType: core.API,
		RateLimit:  5 * time.Second,
	}

	pt.BaseService = *core.NewBaseService(pt, "PassiveTotal", config, bus)
	return pt
}

// OnStart implements the Service interface
func (pt *PassiveTotal) OnStart() error {
	pt.BaseService.OnStart()

	pt.API = pt.Config().GetAPIKey(pt.String())
	if pt.API == nil || pt.API.Username == "" || pt.API.Key == "" {
		pt.Config().Log.Printf("%s: API key data was not provided", pt.String())
	}
	go pt.startRootDomains()
	return nil
}

func (pt *PassiveTotal) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range pt.Config().Domains() {
		pt.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(pt.RateLimit)
	}
}

func (pt *PassiveTotal) executeQuery(domain string) {
	if pt.API == nil || pt.API.Username == "" || pt.API.Key == "" {
		return
	}

	url := pt.restURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, pt.API.Username, pt.API.Key)
	if err != nil {
		pt.Config().Log.Printf("%s: %s: %v", pt.String(), url, err)
		return
	}
	// Extract the subdomain names from the REST API results
	var subs struct {
		Success    bool     `json:"success"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		return
	}
	if !subs.Success {
		return
	}

	pt.SetActive()
	re := pt.Config().DomainRegex(domain)
	for _, s := range subs.Subdomains {
		name := s + "." + domain
		if !re.MatchString(name) {
			continue
		}
		pt.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   name,
			Domain: domain,
			Tag:    pt.SourceType,
			Source: pt.String(),
		})
	}
}

func (pt *PassiveTotal) restURL(domain string) string {
	return "https://api.passivetotal.org/v2/enrichment/subdomains?query=" + domain
}
