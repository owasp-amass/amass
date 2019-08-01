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
	"github.com/OWASP/Amass/utils"
)

// SecurityTrails is the Service that handles access to the SecurityTrails data source.
type SecurityTrails struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewSecurityTrails returns he object initialized, but not yet started.
func NewSecurityTrails(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *SecurityTrails {
	st := &SecurityTrails{
		SourceType: requests.API,
		RateLimit:  time.Second,
	}

	st.BaseService = *services.NewBaseService(st, "SecurityTrails", cfg, bus, pool)
	return st
}

// OnStart implements the Service interface
func (st *SecurityTrails) OnStart() error {
	st.BaseService.OnStart()

	st.API = st.Config().GetAPIKey(st.String())
	if st.API == nil || st.API.Key == "" {
		st.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: API key data was not provided", st.String()),
		)
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
		case req := <-st.DNSRequestChan():
			if st.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < st.RateLimit {
					time.Sleep(st.RateLimit)
				}
				last = time.Now()
				st.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-st.AddrRequestChan():
		case <-st.ASNRequestChan():
		case <-st.WhoisRequestChan():
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
		st.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", st.String(), url, err))
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
			st.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
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
