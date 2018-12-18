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
	var err error
	var url, page string

	key := u.Enum().Config.GetAPIKey(u.String())
	if key == nil {
		return
	}

	url = u.restURL()
	headers := map[string]string{"Content-Type": "application/json"}
	page, err = utils.RequestWebPage(url, nil, headers, key.UID, key.Secret)
	if err != nil {
		u.Enum().Log.Printf("%s: %s: %v", u.String(), url, err)
		return
	}
	// Extract the subdomain names from the REST API results
	type tb struct {
		Name  string
		Score int
	}
	type r struct {
		Related []*tb `json:"tb1"`
		Found   bool  `json:"found"`
	}
	var result r
	if err := json.Unmarshal([]byte(page), &result); err != nil {
		return
	}
	if !result.Found {
		return
	}

	u.SetActive()
	re := u.Enum().Config.DomainRegex(domain)
	for _, n := range result.Related {
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

func (u *Umbrella) restURL() string {
	return "https://www.censys.io/api/v1/search/certificates"
}
