// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// BinaryEdge is the Service that handles access to the BinaryEdge data source.
type BinaryEdge struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewBinaryEdge returns he object initialized, but not yet started.
func NewBinaryEdge(config *core.Config, bus *core.EventBus) *BinaryEdge {
	be := &BinaryEdge{
		SourceType: core.API,
		RateLimit:  2 * time.Second,
	}

	be.BaseService = *core.NewBaseService(be, "BinaryEdge", config, bus)
	return be
}

// OnStart implements the Service interface
func (be *BinaryEdge) OnStart() error {
	be.BaseService.OnStart()

	be.API = be.Config().GetAPIKey(be.String())
	if be.API == nil || be.API.Key == "" {
		be.Config().Log.Printf("%s: API key data was not provided", be.String())
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
		case req := <-be.RequestChan():
			if be.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < be.RateLimit {
					time.Sleep(be.RateLimit)
				}

				be.executeQuery(req.Domain)
				last = time.Now()
			}
		}
	}
}

func (be *BinaryEdge) executeQuery(domain string) {
	if be.API == nil || be.API.Key == "" {
		return
	}

	url := be.restURL(domain)
	headers := map[string]string{
		"X-KEY":        be.API.Key,
		"Content-Type": "application/json",
	}

	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		be.Config().Log.Printf("%s: %s: %v", be.String(), url, err)
		return
	}
	// Extract the subdomain names from the REST API results
	var subs struct {
		Subdomains []string `json:"events"`
	}
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		return
	}

	be.SetActive()
	re := be.Config().DomainRegex(domain)
	for _, name := range subs.Subdomains {
		if !re.MatchString(name) {
			continue
		}
		be.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   name,
			Domain: domain,
			Tag:    be.SourceType,
			Source: be.String(),
		})
	}
}

func (be *BinaryEdge) restURL(domain string) string {
	return "https://api.binaryedge.io/v2/query/domains/subdomain/" + domain
}
