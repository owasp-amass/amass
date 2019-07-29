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

// Sublist3rAPI is the Service that handles access to the Sublist3r API data source.
type Sublist3rAPI struct {
	services.BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewSublist3rAPI returns he object initialized, but not yet started.
func NewSublist3rAPI(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Sublist3rAPI {
	s := &Sublist3rAPI{
		SourceType: requests.API,
		RateLimit:  time.Second,
	}

	s.BaseService = *services.NewBaseService(s, "Sublist3rAPI", cfg, bus, pool)
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
		s.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	}

	// Extract the subdomain names from the REST API results
	var subs []string
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		s.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	} else if len(subs) == 0 {
		s.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", s.String(), url),
		)
		return
	}

	for _, sub := range subs {
		if s.Config().IsDomainInScope(sub) {
			s.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
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
