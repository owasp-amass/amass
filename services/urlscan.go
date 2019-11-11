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

// URLScan is the Service that handles access to the URLScan data source.
type URLScan struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewURLScan returns he object initialized, but not yet started.
func NewURLScan(sys System) *URLScan {
	u := &URLScan{SourceType: requests.API}

	u.BaseService = *NewBaseService(u, "URLScan", sys)
	return u
}

// Type implements the Service interface.
func (u *URLScan) Type() string {
	return u.SourceType
}

// OnStart implements the Service interface.
func (u *URLScan) OnStart() error {
	u.BaseService.OnStart()

	u.API = u.System().Config().GetAPIKey(u.String())
	if u.API == nil || u.API.Key == "" {
		u.System().Config().Log.Printf("%s: API key data was not provided", u.String())
	}

	u.SetRateLimit(2 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (u *URLScan) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, u.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", u.String(), req.Domain))

	url := u.searchURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return
	}
	// Extract the subdomain names from the REST API results
	var results struct {
		Results []struct {
			ID string `json:"_id"`
		} `json:"results"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(page), &results); err != nil {
		return
	}

	var ids []string
	if results.Total > 0 {
		for _, result := range results.Results {
			ids = append(ids, result.ID)
		}
	} else {
		if id := u.attemptSubmission(ctx, req.Domain); id != "" {
			ids = []string{id}
		}
	}

	subs := stringset.New()
	for _, id := range ids {
		subs.Union(u.getSubsFromResult(ctx, id))
	}

	for name := range subs {
		if re.MatchString(name) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: req.Domain,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}
	}
}

func (u *URLScan) getSubsFromResult(ctx context.Context, id string) stringset.Set {
	subs := stringset.New()

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return subs
	}

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, u.String())

	url := u.resultURL(id)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return subs
	}
	// Extract the subdomain names from the REST API results
	var data struct {
		Lists struct {
			IPs        []string `json:"ips"`
			Subdomains []string `json:"linkDomains"`
		} `json:"lists"`
	}
	if err := json.Unmarshal([]byte(page), &data); err == nil {
		subs.InsertMany(data.Lists.Subdomains...)
	}
	return subs
}

func (u *URLScan) attemptSubmission(ctx context.Context, domain string) string {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return ""
	}

	if u.API == nil || u.API.Key == "" {
		return ""
	}

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, u.String())

	headers := map[string]string{
		"API-Key":      u.API.Key,
		"Content-Type": "application/json",
	}
	url := "https://urlscan.io/api/v1/scan/"
	body := strings.NewReader(u.submitBody(domain))
	page, err := http.RequestWebPage(url, body, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return ""
	}

	// Extract the subdomain names from the REST API results
	var result struct {
		Message string `json:"message"`
		ID      string `json:"uuid"`
		API     string `json:"api"`
	}
	if err := json.Unmarshal([]byte(page), &result); err != nil {
		return ""
	}
	if result.Message != "Submission successful" {
		return ""
	}

	// Keep this data source active while waiting for the scan to complete
	for {
		_, err = http.RequestWebPage(result.API, nil, nil, "", "")
		if err == nil || err.Error() != "404 Not Found" {
			break
		}

		u.CheckRateLimit()
		bus.Publish(requests.SetActiveTopic, u.String())
	}
	return result.ID
}

func (u *URLScan) searchURL(domain string) string {
	return fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)
}

func (u *URLScan) resultURL(id string) string {
	return fmt.Sprintf("https://urlscan.io/api/v1/result/%s/", id)
}

func (u *URLScan) submitBody(domain string) string {
	return fmt.Sprintf("{\"url\": \"%s\", \"public\": \"on\", \"customagent\": \"%s\"}", domain, http.UserAgent)
}
