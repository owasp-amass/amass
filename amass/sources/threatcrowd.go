// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// ThreatCrowd is the Service that handles access to the ThreatCrowd data source.
type ThreatCrowd struct {
	core.BaseService

	SourceType string
}

// NewThreatCrowd returns he object initialized, but not yet started.
func NewThreatCrowd(config *core.Config, bus *core.EventBus) *ThreatCrowd {
	t := &ThreatCrowd{SourceType: core.SCRAPE}

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
	for {
		select {
		case <-t.Quit():
			return
		case req := <-t.RequestChan():
			if t.Config().IsDomainInScope(req.Domain) {
				t.executeQuery(req.Domain)
			}
		}
	}
}

func (t *ThreatCrowd) executeQuery(domain string) {
	url := t.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		t.Config().Log.Printf("%s: %s: %v", t.String(), url, err)
		return
	}

	t.SetActive()
	re := t.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		t.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    t.SourceType,
			Source: t.String(),
		})
	}
}

func (t *ThreatCrowd) getURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}
