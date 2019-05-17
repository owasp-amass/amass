// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// AlienVault is the Service that handles access to the AlienVault data source.
type AlienVault struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration

	haveAPIKey bool
}

// NewAlienVault returns he object initialized, but not yet started.
func NewAlienVault(config *core.Config, bus *core.EventBus) *AlienVault {
	a := &AlienVault{
		SourceType: core.API,
		RateLimit:  3 * time.Second,
		haveAPIKey: true,
	}

	a.BaseService = *core.NewBaseService(a, "AlienVault", config, bus)
	return a
}

// OnStart implements the Service interface
func (a *AlienVault) OnStart() error {
	a.BaseService.OnStart()

	a.API = a.Config().GetAPIKey(a.String())
	if a.API == nil || a.API.Key == "" {
		a.haveAPIKey = false
		a.Config().Log.Printf("%s: API key data was not provided", a.String())
	}

	go a.processRequests()
	return nil
}

func (a *AlienVault) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)

	for {
		select {
		case <-a.Quit():
			return
		case req := <-a.RequestChan():
			if a.haveAPIKey && a.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < a.RateLimit {
					time.Sleep(a.RateLimit)
				}

				a.executeQuery(req.Domain)
				last = time.Now()
			}
		}
	}
}

func (a *AlienVault) executeQuery(domain string) {
	url := a.getURL(domain)
	headers := map[string]string{"Content-Type": "application/json", "X-OTX-API-KEY": a.API.Key}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		a.Config().Log.Printf("%s: %s: %v", a.String(), url, err)
		return
	}

	// Extract the subdomain names and IP addresses from the results
	var m struct {
		Subdomains []struct {
			Hostname string `json:"hostname"`
			IP       string `json:"address"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	if len(m.Subdomains) == 0 {
		return
	}

	a.SetActive()
	re := a.Config().DomainRegex(domain)
	for _, sub := range m.Subdomains {
		name := strings.ToLower(sub.Hostname)

		if re.MatchString(name) {
			a.Bus().Publish(core.NewNameTopic, &core.Request{
				Name:   name,
				Domain: domain,
				Tag:    a.SourceType,
				Source: a.String(),
			})

			a.Bus().Publish(core.NewAddrTopic, &core.Request{
				Address: sub.IP,
				Domain:  domain,
				Tag:     a.SourceType,
				Source:  a.String(),
			})
		}
	}
}

func (a *AlienVault) getURL(domain string) string {
	format := "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"

	return fmt.Sprintf(format, domain)
}
