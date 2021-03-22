// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
)

// URLScan is the Service that handles access to the URLScan data source.
type URLScan struct {
	service.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

// NewURLScan returns he object initialized, but not yet started.
func NewURLScan(sys systems.System) *URLScan {
	u := &URLScan{
		SourceType: requests.API,
		sys:        sys,
	}

	u.BaseService = *service.NewBaseService(u, "URLScan")
	return u
}

// Description implements the Service interface.
func (u *URLScan) Description() string {
	return u.SourceType
}

// OnStart implements the Service interface.
func (u *URLScan) OnStart() error {
	u.creds = u.sys.Config().GetDataSourceConfig(u.String()).GetCredentials()

	if u.creds == nil || u.creds.Key == "" {
		u.sys.Config().Log.Printf("%s: API key data was not provided", u.String())
	}

	u.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (u *URLScan) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.DNSRequest); ok {
		u.dnsRequest(ctx, req)
		u.CheckRateLimit()
	}
}

func (u *URLScan) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	numRateLimitChecks(u, 1)
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", u.String(), req.Domain))

	url := u.searchURL(req.Domain)
	page, err := http.RequestWebPage(ctx, url, nil, nil, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
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
		set, err := u.getSubsFromResult(ctx, id)
		if err != nil {
			break
		}

		subs.Union(set)
	}

	for name := range subs {
		if re.MatchString(name) {
			genNewNameEvent(ctx, u.sys, u, name)
		}
	}
}

func (u *URLScan) getSubsFromResult(ctx context.Context, id string) (stringset.Set, error) {
	subs := stringset.New()

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return subs, errors.New("Failed to access the event bus")
	}

	numRateLimitChecks(u, 2)
	url := u.resultURL(id)
	page, err := http.RequestWebPage(ctx, url, nil, nil, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
		return subs, errors.New("HTTP request failed")
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
	return subs, nil
}

func (u *URLScan) attemptSubmission(ctx context.Context, domain string) string {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return ""
	}

	if u.creds == nil || u.creds.Key == "" {
		return ""
	}

	numRateLimitChecks(u, 2)

	headers := map[string]string{
		"API-Key":      u.creds.Key,
		"Content-Type": "application/json",
	}
	url := "https://urlscan.io/api/v1/scan/"
	body := strings.NewReader(u.submitBody(domain))
	page, err := http.RequestWebPage(ctx, url, body, headers, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
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
		_, err = http.RequestWebPage(ctx, result.API, nil, nil, nil)
		if err == nil || err.Error() != "404 Not Found" {
			break
		}

		numRateLimitChecks(u, 2)
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
