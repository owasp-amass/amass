// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// GitHub is the Service that handles access to the GitHub data source.
type GitHub struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewGitHub returns he object initialized, but not yet started.
func NewGitHub(sys System) *GitHub {
	g := &GitHub{SourceType: requests.API}

	g.BaseService = *NewBaseService(g, "GitHub", sys)
	return g
}

// Type implements the Service interface.
func (g *GitHub) Type() string {
	return g.SourceType
}

// OnStart implements the Service interface.
func (g *GitHub) OnStart() error {
	g.BaseService.OnStart()

	g.API = g.System().Config().GetAPIKey(g.String())
	if g.API == nil || g.API.Key == "" {
		g.System().Config().Log.Printf("%s: API key data was not provided", g.String())
	}

	g.SetRateLimit(7 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (g *GitHub) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil || g.API == nil ||
		g.API.Key == "" || req.Name == "" || req.Domain == "" {
		return
	}
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", g.String(), req.Domain))

	nameFilter := stringset.NewStringFilter()
	// This function publishes new subdomain names discovered at the provided URL
	fetchNames := func(u string) {
		bus.Publish(requests.SetActiveTopic, g.String())

		page, err := http.RequestWebPage(u, nil, nil, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", g.String(), u, err))
			return
		}

		// Extract the subdomain names from the page
		for _, sd := range re.FindAllString(page, -1) {
			if name := cleanName(sd); name != "" && !nameFilter.Duplicate(name) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   name,
					Domain: req.Domain,
					Tag:    g.Type(),
					Source: g.String(),
				})
			}
		}
	}

	headers := map[string]string{
		"Authorization": "token " + g.API.Key,
		"Content-Type":  "application/json",
	}
	bus.Publish(requests.SetActiveTopic, g.String())

	urlFilter := stringset.NewStringFilter()
	// Try no more than ten times for search result pages
loop:
	for i := 1; i <= 10; i++ {
		g.CheckRateLimit()
		bus.Publish(requests.SetActiveTopic, g.String())

		u := g.restDNSURL(req.Domain, i)
		// Perform the search using the GitHub API
		page, err := http.RequestWebPage(u, nil, headers, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", g.String(), u, err))
			break loop
		}
		// Extract items from the REST API search results
		var result struct {
			Total int `json:"total_count"`
			Items []struct {
				URL   string  `json:"html_url"`
				Score float64 `json:"score"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(page), &result); err != nil {
			break loop
		}

		// Unique URLs discovered will cause the URLs to be searched for subdomain names
		for _, item := range result.Items {
			if t := g.modifyURL(item.URL); t != "" && !urlFilter.Duplicate(t) {
				go fetchNames(t)
			}
		}
	}
}

func (g *GitHub) restDNSURL(domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://api.github.com/search/code")

	u.RawQuery = url.Values{
		"s":        {"indexed"},
		"type":     {"Code"},
		"o":        {"desc"},
		"q":        {"\"" + domain + "\""},
		"page":     {pn},
		"per_page": {"100"},
	}.Encode()
	return u.String()
}

func (g *GitHub) modifyURL(url string) string {
	m := strings.Replace(url, "https://github.com/", "https://raw.githubusercontent.com/", 1)
	m = strings.Replace(m, "/blob/", "/", 1)
	return m
}
