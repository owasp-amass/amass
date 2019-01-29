// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// DNSTable is the Service that handles access to the DNSTable data source.
type DNSTable struct {
	core.BaseService

	SourceType string
}

// NewDNSTable returns he object initialized, but not yet started.
func NewDNSTable(config *core.Config, bus *core.EventBus) *DNSTable {
	d := &DNSTable{SourceType: core.SCRAPE}

	d.BaseService = *core.NewBaseService(d, "DNSTable", config, bus)
	return d
}

// OnStart implements the Service interface
func (d *DNSTable) OnStart() error {
	d.BaseService.OnStart()

	go d.startRootDomains()
	return nil
}

func (d *DNSTable) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range d.Config().Domains() {
		d.executeQuery(domain)
	}
}

func (d *DNSTable) executeQuery(domain string) {
	url := d.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Config().Log.Printf("%s: %s: %v", d.String(), url, err)
		return
	}

	d.SetActive()
	re := d.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		d.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
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
