// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// BinaryEdge is the Service that handles access to the BinaryEdge data source.
type BinaryEdge struct {
	BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewBinaryEdge returns he object initialized, but not yet started.
func NewBinaryEdge(e *Enumeration) *BinaryEdge {
	be := &BinaryEdge{
		SourceType: API,
		RateLimit:  2 * time.Second,
	}

	be.BaseService = *NewBaseService(e, "BinaryEdge", be)
	return be
}

// OnStart implements the Service interface
func (be *BinaryEdge) OnStart() error {
	be.BaseService.OnStart()

	go be.startRootDomains()
	go be.processRequests()
	return nil
}

func (be *BinaryEdge) processRequests() {
	for {
		select {
		case <-be.PauseChan():
			<-be.ResumeChan()
		case <-be.Quit():
			return
		case <-be.RequestChan():
			// This data source just throws away the checked DNS names
			be.SetActive()
		}
	}
}

func (be *BinaryEdge) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range be.Enum().Config.Domains() {
		be.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(be.RateLimit)
	}
}

func (be *BinaryEdge) executeQuery(domain string) {
	var err error
	var url, page string

	key := be.Enum().Config.GetAPIKey(be.String())
	if key == nil {
		return
	}

	url = be.restURL(domain)
	headers := map[string]string{
		"X-KEY":        key.UID,
		"Content-Type": "application/json",
	}

	page, err = utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		be.Enum().Log.Printf("%s: %s: %v", be.String(), url, err)
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
	re := be.Enum().Config.DomainRegex(domain)
	for _, name := range subs.Subdomains {
		if !re.MatchString(name) {
			continue
		}
		be.Enum().NewNameEvent(&Request{
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
