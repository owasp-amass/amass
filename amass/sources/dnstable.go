// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// DNSTable is the AmassService that handles access to the DNSTable data source.
type DNSTable struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
	filter     *utils.StringFilter
}

// NewDNSTable requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewDNSTable(bus evbus.Bus, config *core.AmassConfig) *DNSTable {
	d := &DNSTable{
		Bus:        bus,
		Config:     config,
		SourceType: core.SCRAPE,
		filter:     utils.NewStringFilter(),
	}

	d.BaseAmassService = *core.NewBaseAmassService("DNSTable", d)
	return d
}

// OnStart implements the AmassService interface
func (d *DNSTable) OnStart() error {
	d.BaseAmassService.OnStart()

	go d.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (d *DNSTable) OnStop() error {
	d.BaseAmassService.OnStop()
	return nil
}

func (d *DNSTable) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range d.Config.Domains() {
		d.executeQuery(domain)
	}
}

func (d *DNSTable) executeQuery(domain string) {
	url := d.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Config.Log.Printf("%s: %s: %v", d.String(), url, err)
		return
	}

	d.SetActive()
	re := d.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		n := cleanName(sd)

		if d.filter.Duplicate(n) {
			continue
		}
		go func(name string) {
			d.Config.MaxFlow.Acquire(1)
			d.Bus.Publish(core.NEWNAME, &core.AmassRequest{
				Name:   name,
				Domain: domain,
				Tag:    d.SourceType,
				Source: d.String(),
			})
		}(n)
	}
}

func (d *DNSTable) getURL(domain string) string {
	format := "https://dnstable.com/domain/%s"

	return fmt.Sprintf(format, domain)
}
