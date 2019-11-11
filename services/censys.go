// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// Censys is the Service that handles access to the Censys data source.
type Censys struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewCensys returns he object initialized, but not yet started.
func NewCensys(sys System) *Censys {
	c := &Censys{SourceType: requests.CERT}

	c.BaseService = *NewBaseService(c, "Censys", sys)
	return c
}

// Type implements the Service interface.
func (c *Censys) Type() string {
	return c.SourceType
}

// OnStart implements the Service interface.
func (c *Censys) OnStart() error {
	c.BaseService.OnStart()

	c.API = c.System().Config().GetAPIKey(c.String())
	if c.API == nil || c.API.Key == "" || c.API.Secret == "" {
		c.System().Config().Log.Printf("%s: API key data was not provided", c.String())
	}

	c.SetRateLimit(3 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (c *Censys) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	c.CheckRateLimit()
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", c.String(), req.Domain))

	if c.API != nil && c.API.Key != "" && c.API.Secret != "" {
		c.apiQuery(ctx, req.Domain)
		return
	}

	c.executeQuery(ctx, req.Domain)
}

type censysRequest struct {
	Query  string   `json:"query"`
	Page   int      `json:"page"`
	Fields []string `json:"fields"`
}

func (c *Censys) apiQuery(ctx context.Context, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	for page := 1; ; page++ {
		bus.Publish(requests.SetActiveTopic, c.String())

		jsonStr, err := json.Marshal(&censysRequest{
			Query:  "parsed.names: " + domain,
			Page:   page,
			Fields: []string{"parsed.names"},
		})
		if err != nil {
			break
		}

		u := c.apiURL()
		body := bytes.NewBuffer(jsonStr)
		headers := map[string]string{"Content-Type": "application/json"}
		resp, err := http.RequestWebPage(u, body, headers, c.API.Key, c.API.Secret)
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", c.String(), u, err))
			break
		}
		// Extract the subdomain names from the certificate information
		var m struct {
			Status   string `json:"status"`
			Metadata struct {
				Page  int `json:"page"`
				Pages int `json:"pages"`
			} `json:"metadata"`
			Results []struct {
				Names []string `json:"parsed.names"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(resp), &m); err != nil || m.Status != "ok" {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", c.String(), u, err))
			break
		} else if len(m.Results) == 0 {
			bus.Publish(requests.LogTopic,
				fmt.Sprintf("%s: %s: The query returned zero results", c.String(), u),
			)
			break
		}

		for _, result := range m.Results {
			for _, name := range result.Names {
				n := strings.TrimSpace(name)
				n = dns.RemoveAsteriskLabel(n)

				if cfg.IsDomainInScope(n) {
					bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
						Name:   n,
						Domain: domain,
						Tag:    c.SourceType,
						Source: c.String(),
					})
				}
			}
		}

		if m.Metadata.Page >= m.Metadata.Pages {
			break
		}
		c.CheckRateLimit()
	}
}

func (c *Censys) apiURL() string {
	return "https://www.censys.io/api/v1/search/certificates"
}

func (c *Censys) executeQuery(ctx context.Context, domain string) {
	var err error
	var url, page string

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(domain)
	if re == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, c.String())

	url = c.webURL(domain)
	page, err = http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", c.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   dns.RemoveAsteriskLabel(cleanName(sd)),
			Domain: domain,
			Tag:    c.SourceType,
			Source: c.String(),
		})
	}
}

func (c *Censys) webURL(domain string) string {
	return fmt.Sprintf("https://www.censys.io/domain/%s/table", domain)
}
