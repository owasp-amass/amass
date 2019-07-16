// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"time"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// Sublist3rAPI is the Service that handles access to the Sublist3r API data source.
type Sublist3rAPI struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewSublist3rAPI returns he object initialized, but not yet started.
func NewSublist3rAPI(config *core.Config, bus *eb.EventBus) *Sublist3rAPI {
	s := &Sublist3rAPI{
		SourceType: core.API,
		RateLimit:  time.Second,
	}

	s.BaseService = *core.NewBaseService(s, "Sublist3rAPI", config, bus)
	return s
}

// OnStart implements the Service interface
func (s *Sublist3rAPI) OnStart() error {
	s.BaseService.OnStart()

	go s.processRequests()
	return nil
}

func (s *Sublist3rAPI) processRequests() {
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

func (s *Sublist3rAPI) executeQuery(domain string) {
	s.SetActive()
	url := s.restURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		s.Config().Log.Printf("%s: %s: %v", s.String(), url, err)
		return
	}

	// Extract the subdomain names from the REST API results
	var subs []string
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		s.Config().Log.Printf("%s: %s: %v", s.String(), url, err)
		return
	} else if len(subs) == 0 {
		s.Config().Log.Printf("%s: %s: The request returned zero results", s.String(), url)
		return
	}

	for _, sub := range subs {
		if s.Config().IsDomainInScope(sub) {
			s.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
				Name:   sub,
				Domain: domain,
				Tag:    s.SourceType,
				Source: s.String(),
			})
		}
	}
}

func (s *Sublist3rAPI) restURL(domain string) string {
	return "https://api.sublist3r.com/search.php?domain=" + domain
}
