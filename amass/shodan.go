// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Shodan is the Service that handles access to the Shodan data source.
type Shodan struct {
	BaseService

	SourceType string
	API        *APIKey
	RateLimit  time.Duration
}

// NewShodan returns he object initialized, but not yet started.
func NewShodan(e *Enumeration) *Shodan {
	s := &Shodan{
		SourceType: API,
		RateLimit:  time.Second,
	}

	s.BaseService = *NewBaseService(e, "Shodan", s)
	return s
}

// OnStart implements the Service interface
func (s *Shodan) OnStart() error {
	s.BaseService.OnStart()

	s.API = s.Enum().Config.GetAPIKey(s.String())
	go s.startRootDomains()
	go s.processRequests()
	return nil
}

func (s *Shodan) processRequests() {
	for {
		select {
		case <-s.PauseChan():
			<-s.ResumeChan()
		case <-s.Quit():
			return
		case <-s.RequestChan():
			// This data source just throws away the checked DNS names
			s.SetActive()
		}
	}
}

func (s *Shodan) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range s.Enum().Config.Domains() {
		s.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(s.RateLimit)
	}
}

func (s *Shodan) executeQuery(domain string) {
	if s.API == nil {
		return
	}

	url := s.restURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		s.Enum().Log.Printf("%s: %s: %v", s.String(), url, err)
		return
	}
	// Extract the subdomain names from the REST API results
	var matches struct {
		Matches []struct {
			Hostnames []string `json:"hostnames"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(page), &matches); err != nil {
		return
	}

	s.SetActive()
	re := s.Enum().Config.DomainRegex(domain)
	for _, match := range matches.Matches {
		for _, host := range match.Hostnames {
			if !re.MatchString(host) {
				continue
			}
			s.Enum().NewNameEvent(&Request{
				Name:   host,
				Domain: domain,
				Tag:    s.SourceType,
				Source: s.String(),
			})
		}
	}
}

func (s *Shodan) restURL(domain string) string {
	return fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=hostname:%s", s.API.Key, domain)
}
