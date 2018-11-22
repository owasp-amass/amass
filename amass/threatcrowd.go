// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// ThreatCrowd is the AmassService that handles access to the ThreatCrowd data source.
type ThreatCrowd struct {
	BaseAmassService

	SourceType string
}

// NewThreatCrowd returns he object initialized, but not yet started.
func NewThreatCrowd(e *Enumeration) *ThreatCrowd {
	t := &ThreatCrowd{SourceType: SCRAPE}

	t.BaseAmassService = *NewBaseAmassService(e, "ThreatCrowd", t)
	return t
}

// OnStart implements the AmassService interface
func (t *ThreatCrowd) OnStart() error {
	t.BaseAmassService.OnStart()

	go t.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (t *ThreatCrowd) OnStop() error {
	t.BaseAmassService.OnStop()
	return nil
}

func (t *ThreatCrowd) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range t.Enum().Config.Domains() {
		t.executeQuery(domain)
	}
}

func (t *ThreatCrowd) executeQuery(domain string) {
	url := t.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		t.Enum().Log.Printf("%s: %s: %v", t.String(), url, err)
		return
	}

	t.SetActive()
	re := t.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    t.SourceType,
			Source: t.String(),
		}

		if t.Enum().DupDataSourceName(req) {
			continue
		}
		t.Enum().Bus.Publish(NEWNAME, req)
	}
}

func (t *ThreatCrowd) getURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}
