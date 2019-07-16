// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// ThreatCrowd is the Service that handles access to the ThreatCrowd data source.
type ThreatCrowd struct {
	core.BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewThreatCrowd returns he object initialized, but not yet started.
func NewThreatCrowd(config *core.Config, bus *eventbus.EventBus) *ThreatCrowd {
	t := &ThreatCrowd{
		SourceType: core.API,
		RateLimit:  10 * time.Second,
	}

	t.BaseService = *core.NewBaseService(t, "ThreatCrowd", config, bus)
	return t
}

// OnStart implements the Service interface
func (t *ThreatCrowd) OnStart() error {
	t.BaseService.OnStart()

	go t.processRequests()
	return nil
}

func (t *ThreatCrowd) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)

	for {
		select {
		case <-t.Quit():
			return
		case req := <-t.DNSRequestChan():
			if t.Config().IsDomainInScope(req.Domain) {
				if delta := time.Now().Sub(last); delta < t.RateLimit {
					time.Sleep(delta)
				}
				last = time.Now()
				t.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-t.AddrRequestChan():
		case <-t.ASNRequestChan():
		case <-t.WhoisRequestChan():
		}
	}
}

func (t *ThreatCrowd) executeQuery(domain string) {
	re := t.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	t.SetActive()
	url := t.getURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		t.Config().Log.Printf("%s: %s: %v", t.String(), url, err)
		return
	}

	// Extract the subdomain names and IP addresses from the results
	var m struct {
		ResponseCode string   `json:"response_code"`
		Subdomains   []string `json:"subdomains"`
		Resolutions  []struct {
			IP string `json:"ip_address"`
		} `json:"resolutions"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	if m.ResponseCode != "1" {
		t.Config().Log.Printf("%s: %s: Response code %s", t.String(), url, m.ResponseCode)
		return
	}

	for _, sub := range m.Subdomains {
		s := strings.ToLower(sub)

		if s != "" && re.MatchString(s) {
			t.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
				Name:   s,
				Domain: domain,
				Tag:    t.SourceType,
				Source: t.String(),
			})
		}
	}

	for _, res := range m.Resolutions {
		t.Bus().Publish(core.NewAddrTopic, &core.AddrRequest{
			Address: res.IP,
			Domain:  domain,
			Tag:     t.SourceType,
			Source:  t.String(),
		})
	}
}

func (t *ThreatCrowd) getURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}
