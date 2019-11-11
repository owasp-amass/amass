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
)

// ThreatCrowd is the Service that handles access to the ThreatCrowd data source.
type ThreatCrowd struct {
	BaseService

	SourceType string
}

// NewThreatCrowd returns he object initialized, but not yet started.
func NewThreatCrowd(sys System) *ThreatCrowd {
	t := &ThreatCrowd{SourceType: requests.API}

	t.BaseService = *NewBaseService(t, "ThreatCrowd", sys)
	return t
}

// Type implements the Service interface.
func (t *ThreatCrowd) Type() string {
	return t.SourceType
}

// OnStart implements the Service interface.
func (t *ThreatCrowd) OnStart() error {
	t.BaseService.OnStart()

	t.SetRateLimit(10 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (t *ThreatCrowd) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	t.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, t.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", t.String(), req.Domain))

	url := t.getURL(req.Domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", t.String(), url, err))
		return
	}

	// Extract the subdomain names and IP addresses from the results
	var m struct {
		ResponseCode string   `json:"response_code"`
		Subdomains   []string `json:"subdomains"`
		Resolutions  []struct {
			IP string `json:"ip_address"`
		} `json:"resolutions"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	if m.ResponseCode != "1" {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Response code %s", t.String(), url, m.ResponseCode),
		)
		return
	}

	for _, sub := range m.Subdomains {
		s := strings.ToLower(sub)

		if s != "" && re.MatchString(s) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   s,
				Domain: req.Domain,
				Tag:    t.SourceType,
				Source: t.String(),
			})
		}
	}

	for _, res := range m.Resolutions {
		bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: res.IP,
			Domain:  req.Domain,
			Tag:     t.SourceType,
			Source:  t.String(),
		})
	}
}

func (t *ThreatCrowd) getURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}
