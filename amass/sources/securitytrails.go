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

// SecurityTrails is the Service that handles access to the SecurityTrails data source.
type SecurityTrails struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewSecurityTrails returns he object initialized, but not yet started.
func NewSecurityTrails(config *core.Config, bus *core.EventBus) *SecurityTrails {
	st := &SecurityTrails{
		SourceType: core.API,
		RateLimit:  time.Second,
	}

	st.BaseService = *core.NewBaseService(st, "SecurityTrails", config, bus)
	return st
}

// OnStart implements the Service interface
func (st *SecurityTrails) OnStart() error {
	st.BaseService.OnStart()

	st.API = st.Config().GetAPIKey(st.String())
	if st.API == nil || st.API.Key == "" {
		st.Config().Log.Printf("%s: API key data was not provided", st.String())
	}

	go st.processRequests()
	return nil
}

func (st *SecurityTrails) processRequests() {
	last := time.Now()

	for {
		select {
		case <-st.Quit():
			return
		case req := <-st.RequestChan():
			if st.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < st.RateLimit {
					time.Sleep(st.RateLimit)
				}
				last = time.Now()
				st.executeQuery(req.Domain)
				last = time.Now()
			}
		}
	}
}

func (st *SecurityTrails) executeQuery(domain string) {
	re := st.Config().DomainRegex(domain)
	if re == nil || st.API == nil || st.API.Key == "" {
		return
	}

	url := st.restURL(domain)
	headers := map[string]string{
		"APIKEY":       st.API.Key,
		"Content-Type": "application/json",
	}

	st.SetActive()
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		st.Config().Log.Printf("%s: %s: %v", st.String(), url, err)
		return
	}
	// Extract the subdomain names from the REST API results
	var subs struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal([]byte(page), &subs); err != nil {
		return
	}

	for _, s := range subs.Subdomains {
		name := strings.ToLower(s) + "." + domain
		if re.MatchString(name) {
			st.Bus().Publish(core.NewNameTopic, &core.Request{
				Name:   name,
				Domain: domain,
				Tag:    st.SourceType,
				Source: st.String(),
			})
		}
	}
}

func (st *SecurityTrails) restURL(domain string) string {
	return fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
}
