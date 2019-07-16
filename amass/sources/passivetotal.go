// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
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
func NewPassiveTotal(config *core.Config, bus *eventbus.EventBus) *PassiveTotal {
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
		pt.Config().Log.Printf("%s: %s: %v", pt.String(), url, err)
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
			pt.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
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
