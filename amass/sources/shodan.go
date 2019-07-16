// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// Shodan is the Service that handles access to the Shodan data source.
type Shodan struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewShodan returns he object initialized, but not yet started.
func NewShodan(config *core.Config, bus *eventbus.EventBus) *Shodan {
	s := &Shodan{
		SourceType: core.API,
		RateLimit:  time.Second,
	}

	s.BaseService = *core.NewBaseService(s, "Shodan", config, bus)
	return s
}

// OnStart implements the Service interface
func (s *Shodan) OnStart() error {
	s.BaseService.OnStart()

	s.API = s.Config().GetAPIKey(s.String())
	if s.API == nil || s.API.Key == "" {
		s.Config().Log.Printf("%s: API key data was not provided", s.String())
	}

	go s.processRequests()
	return nil
}

func (s *Shodan) processRequests() {
	last := time.Now()

	for {
		select {
		case <-s.Quit():
			return
		case req := <-s.DNSRequestChan():
			if s.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < s.RateLimit {
					time.Sleep(s.RateLimit)
				}
				last = time.Now()
				s.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-s.AddrRequestChan():
		case <-s.ASNRequestChan():
		case <-s.WhoisRequestChan():
		}
	}
}

func (s *Shodan) executeQuery(domain string) {
	re := s.Config().DomainRegex(domain)
	if re == nil || s.API == nil || s.API.Key == "" {
		return
	}

	s.SetActive()
	url := s.restURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		s.Config().Log.Printf("%s: %s: %v", s.String(), url, err)
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
				s.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
					Name:   host,
					Domain: domain,
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
