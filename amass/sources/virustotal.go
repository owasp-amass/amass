// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"encoding/json"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// VirusTotal is the Service that handles access to the VirusTotal data source.
type VirusTotal struct {
	core.BaseService

	SourceType string
}

// NewVirusTotal returns he object initialized, but not yet started.
func NewVirusTotal(config *core.Config, bus *core.EventBus) *VirusTotal {
	v := &VirusTotal{SourceType: core.API}

	v.BaseService = *core.NewBaseService(v, "VirusTotal", config, bus)
	return v
}

// OnStart implements the Service interface
func (v *VirusTotal) OnStart() error {
	v.BaseService.OnStart()

	go v.processRequests()
	return nil
}

func (v *VirusTotal) processRequests() {
	for {
		select {
		case <-v.Quit():
			return
		case req := <-v.RequestChan():
			if v.Config().IsDomainInScope(req.Domain) {
				v.executeQuery(req.Domain)
			}
		}
	}
}

func (v *VirusTotal) executeQuery(domain string) {
	url := v.getURL(domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := utils.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		v.Config().Log.Printf("%s: %s: %v", v.String(), url, err)
		return
	}

	// Extract the subdomain names from the results
	var m struct {
		Data []struct {
			ID string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	v.SetActive()
	re := v.Config().DomainRegex(domain)
	for _, data := range m.Data {
		if data.Type != "domain" || !re.MatchString(data.ID) {
			continue
		}

		v.Bus().Publish(core.NewNameTopic, &core.Request{
				Name:   data.ID,
				Domain: domain,
				Tag:    v.SourceType,
				Source: v.String(),
		})
	}
}

func (v *VirusTotal) getURL(domain string) string {
	format := "https://www.virustotal.com/ui/domains/%s/subdomains?limit=40"

	return fmt.Sprintf(format, domain)
}
