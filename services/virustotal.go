// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// VirusTotal is the Service that handles access to the VirusTotal data source.
type VirusTotal struct {
	BaseService

	API        *config.APIKey
	SourceType string
	haveAPIKey bool
}

// NewVirusTotal returns he object initialized, but not yet started.
func NewVirusTotal(sys System) *VirusTotal {
	v := &VirusTotal{
		SourceType: requests.API,
		haveAPIKey: true,
	}

	v.BaseService = *NewBaseService(v, "VirusTotal", sys)
	return v
}

// Type implements the Service interface.
func (v *VirusTotal) Type() string {
	return v.SourceType
}

// OnStart implements the Service interface.
func (v *VirusTotal) OnStart() error {
	v.BaseService.OnStart()

	v.API = v.System().Config().GetAPIKey(v.String())
	if v.API == nil || v.API.Key == "" {
		v.haveAPIKey = false
		v.System().Config().Log.Printf("%s: API key data was not provided", v.String())
	}

	v.SetRateLimit(15 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (v *VirusTotal) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	v.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, v.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", v.String(), req.Domain))

	if v.haveAPIKey {
		v.apiQuery(ctx, req.Domain)
		return
	}

	v.regularQuery(ctx, req.Domain)
}

func (v *VirusTotal) apiQuery(ctx context.Context, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(domain)
	if re == nil {
		return
	}

	url := v.apiURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", v.String(), url, err))
		return
	}

	// Extract the subdomain names and IP addresses from the results
	var m struct {
		ResponseCode int      `json:"response_code"`
		Message      string   `json:"verbose_msg"`
		Subdomains   []string `json:"subdomains"`
		Resolutions  []struct {
			IP string `json:"ip_address"`
		} `json:"resolutions"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	if m.ResponseCode != 1 {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Response code %d: %s", v.String(), url, m.ResponseCode, m.Message),
		)
		return
	}

	for _, sub := range m.Subdomains {
		s := strings.ToLower(sub)

		if re.MatchString(s) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   s,
				Domain: domain,
				Tag:    v.SourceType,
				Source: v.String(),
			})
		}
	}

	for _, res := range m.Resolutions {
		bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: res.IP,
			Domain:  domain,
			Tag:     v.SourceType,
			Source:  v.String(),
		})
	}
}

func (v *VirusTotal) apiURL(domain string) string {
	u, _ := url.Parse("https://www.virustotal.com/vtapi/v2/domain/report")
	u.RawQuery = url.Values{"apikey": {v.API.Key}, "domain": {domain}}.Encode()

	return u.String()
}

func (v *VirusTotal) regularQuery(ctx context.Context, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(domain)
	if re == nil {
		return
	}

	url := v.getURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", v.String(), url, err))
		return
	}

	// Extract the subdomain names from the results
	var m struct {
		Data []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	for _, data := range m.Data {
		if data.Type == "domain" && re.MatchString(data.ID) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   data.ID,
				Domain: domain,
				Tag:    v.SourceType,
				Source: v.String(),
			})
		}
	}
}

func (v *VirusTotal) getURL(domain string) string {
	format := "https://www.virustotal.com/ui/domains/%s/subdomains?limit=40"

	return fmt.Sprintf(format, domain)
}
