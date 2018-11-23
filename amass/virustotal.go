// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// VirusTotal is the AmassService that handles access to the VirusTotal data source.
type VirusTotal struct {
	BaseAmassService

	SourceType string
}

// NewVirusTotal returns he object initialized, but not yet started.
func NewVirusTotal(e *Enumeration) *VirusTotal {
	v := &VirusTotal{SourceType: SCRAPE}

	v.BaseAmassService = *NewBaseAmassService(e, "VirusTotal", v)
	return v
}

// OnStart implements the AmassService interface
func (v *VirusTotal) OnStart() error {
	v.BaseAmassService.OnStart()

	go v.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (v *VirusTotal) OnStop() error {
	v.BaseAmassService.OnStop()
	return nil
}

func (v *VirusTotal) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range v.Enum().Config.Domains() {
		v.executeQuery(domain)
	}
}

func (v *VirusTotal) executeQuery(domain string) {
	re := v.Enum().Config.DomainRegex(domain)
	url := v.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		v.Enum().Log.Printf("%s: %s: %v", v.String(), url, err)
		return
	}

	v.SetActive()
	for _, sd := range re.FindAllString(page, -1) {
		v.Enum().NewNameEvent(&AmassRequest{
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
