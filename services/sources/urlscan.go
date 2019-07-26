// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/stringset"
	"github.com/OWASP/Amass/utils"
)

// URLScan is the Service that handles access to the URLScan data source.
type URLScan struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewURLScan returns he object initialized, but not yet started.
func NewURLScan(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *URLScan {
	u := &URLScan{
		SourceType: requests.API,
		RateLimit:  2 * time.Second,
	}

	u.BaseService = *services.NewBaseService(u, "URLScan", cfg, bus, pool)
	return u
}

// OnStart implements the Service interface
func (u *URLScan) OnStart() error {
	u.BaseService.OnStart()

	u.API = u.Config().GetAPIKey(u.String())
	if u.API == nil || u.API.Key == "" {
		u.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: API key data was not provided", u.String()),
		)
	}

	go u.processRequests()
	return nil
}

func (u *URLScan) processRequests() {
	last := time.Now()

	for {
		select {
		case <-u.Quit():
			return
		case req := <-u.DNSRequestChan():
			if u.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < u.RateLimit {
					time.Sleep(u.RateLimit)
				}
				last = time.Now()
				u.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-u.AddrRequestChan():
		case <-u.ASNRequestChan():
		case <-u.WhoisRequestChan():
		}
	}
}

func (u *URLScan) executeQuery(domain string) {
	re := u.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	u.SetActive()
	url := u.searchURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
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
		if id := u.attemptSubmission(domain); id != "" {
			ids = []string{id}
		}
	}

	subs := stringset.New()
	for _, id := range ids {
		subs.Union(u.getSubsFromResult(id))
	}

	for _, name := range subs.ToSlice() {
		if re.MatchString(name) {
			u.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}
	}
}

func (u *URLScan) getSubsFromResult(id string) stringset.Set {
	subs := stringset.New()

	url := u.resultURL(id)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
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

func (u *URLScan) attemptSubmission(domain string) string {
	if u.API == nil || u.API.Key == "" {
		return ""
	}

	headers := map[string]string{
		"API-Key":      u.API.Key,
		"Content-Type": "application/json",
	}
	url := "https://urlscan.io/api/v1/scan/"
	body := strings.NewReader(u.submitBody(domain))
	page, err := utils.RequestWebPage(url, body, headers, "", "")
	if err != nil {
		u.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", u.String(), url, err))
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
		_, err = utils.RequestWebPage(result.API, nil, nil, "", "")
		if err == nil || err.Error() != "404 Not Found" {
			break
		}
		u.SetActive()
		time.Sleep(u.RateLimit)
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
	return fmt.Sprintf("{\"url\": \"%s\", \"public\": \"on\", \"customagent\": \"%s\"}", domain, utils.UserAgent)
}
