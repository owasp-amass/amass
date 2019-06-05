// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// URLScan is the Service that handles access to the URLScan data source.
type URLScan struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewURLScan returns he object initialized, but not yet started.
func NewURLScan(config *core.Config, bus *core.EventBus) *URLScan {
	u := &URLScan{
		SourceType: core.API,
		RateLimit:  2 * time.Second,
	}

	u.BaseService = *core.NewBaseService(u, "URLScan", config, bus)
	return u
}

// OnStart implements the Service interface
func (u *URLScan) OnStart() error {
	u.BaseService.OnStart()

	u.API = u.Config().GetAPIKey(u.String())
	if u.API == nil || u.API.Key == "" {
		u.Config().Log.Printf("%s: API key data was not provided", u.String())
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
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
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

	var subs []string
	for _, id := range ids {
		subs = utils.UniqueAppend(subs, u.getSubsFromResult(id)...)
	}

	for _, name := range subs {
		if re.MatchString(name) {
			u.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    u.SourceType,
				Source: u.String(),
			})
		}
	}
}

func (u *URLScan) getSubsFromResult(id string) []string {
	var subs []string

	url := u.resultURL(id)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
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
		subs = utils.UniqueAppend(subs, data.Lists.Subdomains...)
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
		u.Config().Log.Printf("%s: %s: %v", u.String(), url, err)
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
