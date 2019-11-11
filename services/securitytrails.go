// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// SecurityTrails is the Service that handles access to the SecurityTrails data source.
type SecurityTrails struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewSecurityTrails returns he object initialized, but not yet started.
func NewSecurityTrails(sys System) *SecurityTrails {
	st := &SecurityTrails{SourceType: requests.API}

	st.BaseService = *NewBaseService(st, "SecurityTrails", sys)
	return st
}

// Type implements the Service interface.
func (st *SecurityTrails) Type() string {
	return st.SourceType
}

// OnStart implements the Service interface.
func (st *SecurityTrails) OnStart() error {
	st.BaseService.OnStart()

	st.API = st.System().Config().GetAPIKey(st.String())
	if st.API == nil || st.API.Key == "" {
		st.System().Config().Log.Printf("%s: API key data was not provided", st.String())
	}

	st.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (st *SecurityTrails) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil || st.API == nil ||
		st.API.Key == "" || req.Name == "" || req.Domain == "" {
		return
	}

	st.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, st.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", st.String(), req.Domain))

	url := st.restDNSURL(req.Domain)
	headers := map[string]string{
		"APIKEY":       st.API.Key,
		"Content-Type": "application/json",
	}

	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", st.String(), url, err))
		return
	}
	// Extract the subdomain names from the REST API results
	var subs struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		return
	}

	for _, s := range subs.Subdomains {
		name := strings.ToLower(s) + "." + req.Domain
		if re.MatchString(name) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: req.Domain,
				Tag:    st.SourceType,
				Source: st.String(),
			})
		}
	}
}

// OnWhoisRequest implements the Service interface.
func (st *SecurityTrails) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if st.API == nil || st.API.Key == "" || req.Domain == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	st.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, st.String())

	url := st.restWhoisURL(req.Domain)
	headers := map[string]string{
		"APIKEY":       st.API.Key,
		"Content-Type": "application/json",
	}

	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", st.String(), url, err))
		return
	}
	// Extract the whois information from the REST API results
	var assoc struct {
		Records []struct {
			Domain string `json:"hostname"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(page), &assoc); err != nil {
		return
	}

	matches := stringset.New()
	for _, record := range assoc.Records {
		if name := strings.ToLower(record.Domain); name != "" {
			matches.Insert(strings.TrimSpace(name))
		}
	}

	if len(matches) > 0 {
		bus.Publish(requests.NewWhoisTopic, &requests.WhoisRequest{
			Domain:     req.Domain,
			NewDomains: matches.Slice(),
			Tag:        st.SourceType,
			Source:     st.String(),
		})
	}
}

func (st *SecurityTrails) restDNSURL(domain string) string {
	return fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
}

func (st *SecurityTrails) restWhoisURL(domain string) string {
	return fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/associated", domain)
}
