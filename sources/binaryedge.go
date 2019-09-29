// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
)

// BinaryEdge is the Service that handles access to the BinaryEdge data source.
type BinaryEdge struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewBinaryEdge returns he object initialized, but not yet started.
func NewBinaryEdge(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *BinaryEdge {
	be := &BinaryEdge{
		SourceType: requests.API,
		RateLimit:  2 * time.Second,
	}

	be.BaseService = *services.NewBaseService(be, "BinaryEdge", cfg, bus, pool)
	return be
}

// OnStart implements the Service interface
func (be *BinaryEdge) OnStart() error {
	be.BaseService.OnStart()

	be.API = be.Config().GetAPIKey(be.String())
	if be.API == nil || be.API.Key == "" {
		be.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: API key data was not provided", be.String()))
	}

	go be.processRequests()
	return nil
}

func (be *BinaryEdge) processRequests() {
	last := time.Now()

	for {
		select {
		case <-be.Quit():
			return
		case req := <-be.DNSRequestChan():
			if be.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < be.RateLimit {
					time.Sleep(be.RateLimit)
				}

				be.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-be.AddrRequestChan():
		case <-be.ASNRequestChan():
		case <-be.WhoisRequestChan():
		}
	}
}

func (be *BinaryEdge) executeQuery(domain string) {
	if be.API == nil || be.API.Key == "" {
		return
	}

	re := be.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	url := be.restURL(domain)
	headers := map[string]string{
		"X-KEY":        be.API.Key,
		"Content-Type": "application/json",
	}

	be.SetActive()
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		be.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", be.String(), url, err))
		return
	}
	// Extract the subdomain names from the REST API results
	var subs struct {
		Subdomains []string `json:"events"`
	}
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		return
	}

	for _, name := range subs.Subdomains {
		if re.MatchString(name) {
			be.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    be.SourceType,
				Source: be.String(),
			})
		}
	}
}

func (be *BinaryEdge) restURL(domain string) string {
	return "https://api.binaryedge.io/v2/query/domains/subdomain/" + domain
}
