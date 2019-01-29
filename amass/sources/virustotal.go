// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

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
	v := &VirusTotal{SourceType: core.SCRAPE}

	v.BaseService = *core.NewBaseService(v, "VirusTotal", config, bus)
	return v
}

// OnStart implements the Service interface
func (v *VirusTotal) OnStart() error {
	v.BaseService.OnStart()

	go v.startRootDomains()
	return nil
}

func (v *VirusTotal) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range v.Config().Domains() {
		v.executeQuery(domain)
	}
}

func (v *VirusTotal) executeQuery(domain string) {
	re := v.Config().DomainRegex(domain)
	url := v.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		v.Config().Log.Printf("%s: %s: %v", v.String(), url, err)
		return
	}

	v.SetActive()
	for _, sd := range re.FindAllString(page, -1) {
		v.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    v.SourceType,
			Source: v.String(),
		})
	}
}

func (v *VirusTotal) getURL(domain string) string {
	format := "https://www.virustotal.com/en/domain/%s/information/"

	return fmt.Sprintf(format, domain)
}
