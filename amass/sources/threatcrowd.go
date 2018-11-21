// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// ThreatCrowd is the AmassService that handles access to the ThreatCrowd data source.
type ThreatCrowd struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

// NewThreatCrowd requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewThreatCrowd(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *ThreatCrowd {
	t := &ThreatCrowd{
		Bus:        bus,
		Config:     config,
		SourceType: core.SCRAPE,
	}

	t.BaseAmassService = *core.NewBaseAmassService(e, "ThreatCrowd", t)
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
	for _, domain := range t.Config.Domains() {
		t.executeQuery(domain)
	}
}

func (t *ThreatCrowd) executeQuery(domain string) {
	url := t.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		t.Config.Log.Printf("%s: %s: %v", t.String(), url, err)
		return
	}

	t.SetActive()
	re := t.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &core.AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    t.SourceType,
			Source: t.String(),
		}

		if t.Enum().DupDataSourceName(req) {
			continue
		}
		t.Bus.Publish(core.NEWNAME, req)
	}
}

func (t *ThreatCrowd) getURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}
