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
}

// NewDNSTable requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewDNSTable(bus evbus.Bus, config *core.AmassConfig) *DNSTable {
	d := &DNSTable{
		Bus:        bus,
		Config:     config,
		SourceType: core.SCRAPE,
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

		if core.DataSourceNameFilter.Duplicate(n) {
			continue
		}

		d.Bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   n,
			Domain: domain,
			Tag:    d.SourceType,
			Source: d.String(),
		})
	}
}

func (d *DNSTable) getURL(domain string) string {
	format := "https://dnstable.com/domain/%s"

	return fmt.Sprintf(format, domain)
}
