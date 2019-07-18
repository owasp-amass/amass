// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// Spyse is the Service that handles access to the Spyse data source.
type Spyse struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
}

// NewSpyse returns he object initialized, but not yet started.
func NewSpyse(config *core.Config, bus *eb.EventBus) *Spyse {
	s := &Spyse{SourceType: core.API}

	s.BaseService = *core.NewBaseService(s, "Spyse", config, bus)
	return s
}

// OnStart implements the Service interface
func (s *Spyse) OnStart() error {
	s.BaseService.OnStart()

	s.API = s.Config().GetAPIKey(s.String())
	if s.API == nil || s.API.Key == "" {
		s.Config().Log.Printf("%s: API key data was not provided", s.String())
	}

	go s.processRequests()
	return nil
}

func (s *Spyse) processRequests() {
	for {
		select {
		case <-s.Quit():
			return
		case req := <-s.DNSRequestChan():
			if s.Config().IsDomainInScope(req.Domain) {
				if s.API == nil || s.API.Key == "" {
					s.executeSubdomainQuery(req.Domain)
				} else {
					s.executePagedRequest(req.Domain, s.subdomainQueryAPI)
					s.certQueryAPI(req.Domain)
				}
			}
		case <-s.AddrRequestChan():
		case <-s.ASNRequestChan():
		case <-s.WhoisRequestChan():
		}
	}
}

func (s *Spyse) executePagedRequest(domain string, apiFunc func(string, int) (int, error)) {
	for p := 1; ; p++ {
		count, err := apiFunc(domain, p)
		if err != nil {
			break
		} else if (count % 30) > 0 {
			// exceeded total page count for this query
			break
		} else if (count / 30) < p {
			break
		}
	}
}

func (s *Spyse) subdomainQueryAPI(domain string, page int) (int, error) {
	u := s.getAPIURL(domain, page)
	response, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		s.Config().Log.Printf("%s: %s: %v", s.String(), u, err)
		return 0, err
	}

	var results struct {
		Records []struct {
			Domain string `json:"domain"`
		} `json:"records"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal([]byte(response), &results); err != nil {
		s.Config().Log.Printf("%s: Failed to unmarshal JSON: %v", s.String(), err)
		return 0, err
	}

	s.SetActive()
	re := s.Config().DomainRegex(domain)
	for _, record := range results.Records {
		n := re.FindString(record.Domain)
		if n == "" {
			continue
		}

		s.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   cleanName(n),
			Domain: record.Domain,
			Tag:    s.SourceType,
			Source: s.String(),
		})
	}

	return results.Count, nil
}

func (s *Spyse) executeSubdomainQuery(domain string) {
	re := s.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	s.SetActive()
	url := s.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		s.Config().Log.Printf("%s: %s: %v", s.String(), url, err)
		return
	}

	count := 0
	for _, sd := range re.FindAllString(page, -1) {
		s.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    s.SourceType,
			Source: s.String(),
		})
		count += 1
	}
}

func (s *Spyse) certQueryAPI(domain string) error {
	u := s.getCertAPIURL(domain)
	response, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		s.Config().Log.Printf("%s: %s: %v", s.String(), u, err)
		return err
	}

	var results []struct {
		Records []struct {
			Domain string `json:"domain"`
		} `json:"domains"`
	}

	if err := json.Unmarshal([]byte(response), &results); err != nil {
		s.Config().Log.Printf("%s: Failed to unmarshal JSON: %v", s.String(), err)
		return err
	}

	s.SetActive()
	count := 0
	re := s.Config().DomainRegex(domain)
	for _, result := range results {
		for _, record := range result.Records {
			count += 1
			n := re.FindString(record.Domain)
			if n == "" {
				continue
			}

			s.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
				Name:   cleanName(n),
				Domain: record.Domain,
				Tag:    s.SourceType,
				Source: s.String(),
			})
		}
	}

	return nil
}

func (s *Spyse) getAPIURL(domain string, page int) string {
	return fmt.Sprintf("https://api.spyse.com/v1/subdomains?api_token=%s&domain=%s&page=%d", s.API.Key, domain, page)
}

func (s *Spyse) getCertAPIURL(domain string) string {
	return fmt.Sprintf(`https://api.spyse.com/v1/ssl-certificates?api_token=%s&q=domain:"%s"`, s.API.Key, domain)
}

func (s *Spyse) getURL(domain string) string {
	return fmt.Sprintf("https://findsubdomains.com/subdomains-of/%s", domain)
}
