// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// Spyse is the Service that handles access to the Spyse data source.
type Spyse struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewSpyse returns he object initialized, but not yet started.
func NewSpyse(sys System) *Spyse {
	s := &Spyse{SourceType: requests.API}

	s.BaseService = *NewBaseService(s, "Spyse", sys)
	return s
}

// Type implements the Service interface.
func (s *Spyse) Type() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *Spyse) OnStart() error {
	s.BaseService.OnStart()

	s.API = s.System().Config().GetAPIKey(s.String())
	if s.API == nil || s.API.Key == "" {
		s.System().Config().Log.Printf("%s: API key data was not provided", s.String())
	}

	s.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (s *Spyse) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", s.String(), req.Domain))

	if s.API == nil || s.API.Key == "" {
		s.executeSubdomainQuery(ctx, req.Domain)
	} else {
		s.executePagedRequest(ctx, req.Domain, s.subdomainQueryAPI)
		s.certQueryAPI(ctx, req.Domain)
	}
}

func (s *Spyse) executePagedRequest(ctx context.Context, domain string, apiFunc func(context.Context, string, int) (int, error)) {
	for p := 1; ; p++ {
		count, err := apiFunc(ctx, domain, p)
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

func (s *Spyse) subdomainQueryAPI(ctx context.Context, domain string, page int) (int, error) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return 0, errors.New("Failed to obtain the config and/or eventbus from the Context")
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())

	u := s.getAPIURL(domain, page)
	response, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), u, err))
		return 0, err
	}

	var results struct {
		Records []struct {
			Domain string `json:"domain"`
		} `json:"records"`
		Count int `json:"count"`
	}

	if err := json.Unmarshal([]byte(response), &results); err != nil {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to unmarshal JSON: %v", s.String(), err),
		)
		return 0, err
	}

	re := cfg.DomainRegex(domain)
	for _, record := range results.Records {
		n := re.FindString(record.Domain)
		if n == "" {
			continue
		}

		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(n),
			Domain: record.Domain,
			Tag:    s.SourceType,
			Source: s.String(),
		})
	}

	return results.Count, nil
}

func (s *Spyse) executeSubdomainQuery(ctx context.Context, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	domainRE := strings.Replace(domain, ".", "[.]", -1)
	re := regexp.MustCompile(`title="(` + dns.SUBRE + domainRE + ")")
	if re == nil {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())

	url := s.getURL(domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		return
	}

	subs := re.FindAllStringSubmatch(page, -1)

	matches := stringset.New()
	for _, match := range subs {
		sub := match[1]
		if sub != "" {
			matches.Insert(strings.TrimSpace(sub))
		}
	}

	for sd := range matches {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    s.SourceType,
			Source: s.String(),
		})
	}
}

func (s *Spyse) certQueryAPI(ctx context.Context, domain string) error {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return errors.New("Failed to obtain the config and/or eventbus from the Context")
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, s.String())

	u := s.getCertAPIURL(domain)
	response, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", s.String(), u, err))
		return err
	}

	var results []struct {
		Records []struct {
			Domain string `json:"domain"`
		} `json:"domains"`
	}

	if err := json.Unmarshal([]byte(response), &results); err != nil {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to unmarshal JSON: %v", s.String(), err),
		)
		return err
	}

	count := 0
	re := cfg.DomainRegex(domain)
	for _, result := range results {
		for _, record := range result.Records {
			count++
			n := re.FindString(record.Domain)
			if n == "" {
				continue
			}

			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
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
