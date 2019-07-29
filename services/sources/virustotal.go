// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// VirusTotal is the Service that handles access to the VirusTotal data source.
type VirusTotal struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration

	haveAPIKey bool
}

// NewVirusTotal returns he object initialized, but not yet started.
func NewVirusTotal(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *VirusTotal {
	v := &VirusTotal{
		SourceType: requests.API,
		RateLimit:  15 * time.Second,
		haveAPIKey: true,
	}

	v.BaseService = *services.NewBaseService(v, "VirusTotal", cfg, bus, pool)
	return v
}

// OnStart implements the Service interface
func (v *VirusTotal) OnStart() error {
	v.BaseService.OnStart()

	v.API = v.Config().GetAPIKey(v.String())
	if v.API == nil || v.API.Key == "" {
		v.haveAPIKey = false
		v.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: API key data was not provided", v.String()),
		)
	}

	go v.processRequests()
	return nil
}

func (v *VirusTotal) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)

	for {
		select {
		case <-v.Quit():
			return
		case req := <-v.DNSRequestChan():
			if v.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < v.RateLimit {
					time.Sleep(v.RateLimit)
				}
				last = time.Now()
				if v.haveAPIKey {
					v.apiQuery(req.Domain)
				} else {
					v.regularQuery(req.Domain)
				}
				last = time.Now()
			}
		case <-v.AddrRequestChan():
		case <-v.ASNRequestChan():
		case <-v.WhoisRequestChan():
		}
	}
}

func (v *VirusTotal) apiQuery(domain string) {
	re := v.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	v.SetActive()
	url := v.apiURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		v.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", v.String(), url, err))
		return
	}

	// Extract the subdomain names and IP addresses from the results
	var m struct {
		ResponseCode int      `json:"response_code"`
		Message      string   `json:"verbose_msg"`
		Subdomains   []string `json:"subdomains"`
		Resolutions  []struct {
			IP string `json:"ip_address"`
		} `json:"resolutions"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	if m.ResponseCode != 1 {
		v.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Response code %d: %s", v.String(), url, m.ResponseCode, m.Message),
		)
		return
	}

	for _, sub := range m.Subdomains {
		s := strings.ToLower(sub)

		if re.MatchString(s) {
			v.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   s,
				Domain: domain,
				Tag:    v.SourceType,
				Source: v.String(),
			})
		}
	}

	for _, res := range m.Resolutions {
		v.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: res.IP,
			Domain:  domain,
			Tag:     v.SourceType,
			Source:  v.String(),
		})
	}
}

func (v *VirusTotal) apiURL(domain string) string {
	u, _ := url.Parse("https://www.virustotal.com/vtapi/v2/domain/report")
	u.RawQuery = url.Values{"apikey": {v.API.Key}, "domain": {domain}}.Encode()

	return u.String()
}

func (v *VirusTotal) regularQuery(domain string) {
	re := v.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	v.SetActive()
	url := v.getURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		v.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", v.String(), url, err))
		return
	}

	// Extract the subdomain names from the results
	var m struct {
		Data []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	for _, data := range m.Data {
		if data.Type == "domain" && re.MatchString(data.ID) {
			v.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   data.ID,
				Domain: domain,
				Tag:    v.SourceType,
				Source: v.String(),
			})
		}
	}
}

func (v *VirusTotal) getURL(domain string) string {
	format := "https://www.virustotal.com/ui/domains/%s/subdomains?limit=40"

	return fmt.Sprintf(format, domain)
}
