// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Umbrella is the Service that handles access to the Umbrella data source.
type Umbrella struct {
	BaseService

	API        *APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewUmbrella returns he object initialized, but not yet started.
func NewUmbrella(e *Enumeration) *Umbrella {
	u := &Umbrella{
		SourceType: API,
		RateLimit:  time.Second,
	}

	u.BaseService = *NewBaseService(e, "Umbrella", u)
	return u
}

// OnStart implements the Service interface
func (u *Umbrella) OnStart() error {
	u.BaseService.OnStart()

	u.API = u.Enum().Config.GetAPIKey(u.String())
	if u.API == nil || u.API.Key == "" {
		u.Enum().Log.Printf("%s: API key data was not provided", u.String())
	}
	go u.startRootDomains()
	go u.processRequests()
	return nil
}

func (u *Umbrella) processRequests() {
	for {
		select {
		case <-u.PauseChan():
			<-u.ResumeChan()
		case <-u.Quit():
			return
		case <-u.RequestChan():
			// This data source just throws away the checked DNS names
			u.SetActive()
		}
	}
}

func (u *Umbrella) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range u.Enum().Config.Domains() {
		u.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(u.RateLimit)
	}
}

func (u *Umbrella) executeQuery(domain string) {
	if u.API == nil || u.API.Key == "" {
		return
	}

	url := u.restURL(domain)
	headers := map[string]string{
		"Authorization": "Bearer " + u.API.Key,
		"Content-Type":  "application/json",
	}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		u.Enum().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}
	// Extract the subdomain names from the REST API results
	var results struct {
		Related []struct {
			Name string
		} `json:"tb1"`
		Found bool `json:"found"`
	}
	if err := json.Unmarshal([]byte(page), &results); err != nil {
		return
	}
	if !results.Found {
		return
	}

	u.SetActive()
	re := u.Enum().Config.DomainRegex(domain)
	for _, n := range results.Related {
		if !re.MatchString(n.Name) {
			continue
		}
		u.Enum().NewNameEvent(&Request{
			Name:   n.Name,
			Domain: domain,
			Tag:    u.SourceType,
			Source: u.String(),
		})
	}
}

func (u *Umbrella) restURL(domain string) string {
	return "https://investigate.api.umbrella.com/links/name/" + domain + ".json"
}
