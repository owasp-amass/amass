// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// CertSpotter is the Service that handles access to the CertSpotter data source.
type CertSpotter struct {
	BaseService

	SourceType string
}

// NewCertSpotter returns he object initialized, but not yet started.
func NewCertSpotter(sys System) *CertSpotter {
	c := &CertSpotter{SourceType: requests.CERT}

	c.BaseService = *NewBaseService(c, "CertSpotter", sys)
	return c
}

// Type implements the Service interface.
func (c *CertSpotter) Type() string {
	return c.SourceType
}

// OnStart implements the Service interface.
func (c *CertSpotter) OnStart() error {
	c.BaseService.OnStart()

	c.SetRateLimit(2 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (c *CertSpotter) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	c.CheckRateLimit()

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, c.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", c.String(), req.Domain))

	url := c.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", c.String(), url, err))
		return
	}
	// Extract the subdomain names from the certificate information
	var m []struct {
		Names []string `json:"dns_names"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	for _, result := range m {
		for _, name := range result.Names {
			if re.MatchString(name) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   dns.RemoveAsteriskLabel(name),
					Domain: req.Domain,
					Tag:    c.SourceType,
					Source: c.String(),
				})
			}
		}
	}
}

func (c *CertSpotter) getURL(domain string) string {
	u, _ := url.Parse("https://api.certspotter.com/v1/issuances")

	u.RawQuery = url.Values{
		"domain":             {domain},
		"include_subdomains": {"true"},
		"match_wildcards":    {"true"},
		"expand":             {"dns_names"},
	}.Encode()
	return u.String()
}
