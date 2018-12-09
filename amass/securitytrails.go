// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// SecurityTrails is the Service that handles access to the SecurityTrails data source.
type SecurityTrails struct {
	BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewSecurityTrails returns he object initialized, but not yet started.
func NewSecurityTrails(e *Enumeration) *SecurityTrails {
	st := &SecurityTrails{
		SourceType: API,
		RateLimit:  time.Second,
	}

	st.BaseService = *NewBaseService(e, "SecurityTrails", st)
	return st
}

// OnStart implements the Service interface
func (st *SecurityTrails) OnStart() error {
	st.BaseService.OnStart()

	go st.startRootDomains()
	go st.processRequests()
	return nil
}

func (st *SecurityTrails) processRequests() {
	for {
		select {
		case <-st.PauseChan():
			<-st.ResumeChan()
		case <-st.Quit():
			return
		case <-st.RequestChan():
			// This data source just throws away the checked DNS names
			st.SetActive()
		}
	}
}

func (st *SecurityTrails) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range st.Enum().Config.Domains() {
		st.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(st.RateLimit)
	}
}

func (st *SecurityTrails) executeQuery(domain string) {
	var err error
	var url, page string

	key := st.Enum().Config.GetAPIKey(st.String())
	if key == nil {
		return
	}

	url = st.restURL(domain)
	headers := map[string]string{
		"APIKEY":       key.UID,
		"Content-Type": "application/json",
	}

	page, err = utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		st.Enum().Log.Printf("%s: %s: %v", st.String(), url, err)
		return
	}
	// Extract the subdomain names from the REST API results
	type subJSON struct {
		Subdomains []string `json:"subdomains"`
	}
	var subs subJSON
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		return
	}

	st.SetActive()
	re := st.Enum().Config.DomainRegex(domain)
	for _, s := range subs.Subdomains {
		name := s + "." + domain
		if !re.MatchString(name) {
			continue
		}
		st.Enum().NewNameEvent(&Request{
			Name:   name,
			Domain: domain,
			Tag:    st.SourceType,
			Source: st.String(),
		})
	}
}

func (st *SecurityTrails) restURL(domain string) string {
	return fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
}
