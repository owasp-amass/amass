// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// DNSTable is the AmassService that handles access to the DNSTable data source.
type DNSTable struct {
	core.BaseAmassService

	SourceType string
}

// NewDNSTable returns he object initialized, but not yet started.
func NewDNSTable(e *core.Enumeration) *DNSTable {
	d := &DNSTable{SourceType: core.SCRAPE}

	d.BaseAmassService = *core.NewBaseAmassService(e, "DNSTable", d)
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
	for _, domain := range d.Enum().Config.Domains() {
		d.executeQuery(domain)
	}
}

func (d *DNSTable) executeQuery(domain string) {
	url := d.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Enum().Log.Printf("%s: %s: %v", d.String(), url, err)
		return
	}

	d.SetActive()
	re := d.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &core.AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    d.SourceType,
			Source: d.String(),
		}

		if d.Enum().DupDataSourceName(req) {
			continue
		}
		d.Enum().Bus.Publish(core.NEWNAME, req)
	}
}

func (d *DNSTable) getURL(domain string) string {
	format := "https://dnstable.com/domain/%s"

	return fmt.Sprintf(format, domain)
}
