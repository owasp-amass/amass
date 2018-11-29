// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// DNSTable is the Service that handles access to the DNSTable data source.
type DNSTable struct {
	BaseService

	SourceType string
}

// NewDNSTable returns he object initialized, but not yet started.
func NewDNSTable(e *Enumeration) *DNSTable {
	d := &DNSTable{SourceType: SCRAPE}

	d.BaseService = *NewBaseService(e, "DNSTable", d)
	return d
}

// OnStart implements the Service interface
func (d *DNSTable) OnStart() error {
	d.BaseService.OnStart()

	go d.startRootDomains()
	go d.processRequests()
	return nil
}

func (d *DNSTable) processRequests() {
	for {
		select {
		case <-d.PauseChan():
			<-d.ResumeChan()
		case <-d.Quit():
			return
		case <-d.RequestChan():
			// This data source just throws away the checked DNS names
			d.SetActive()
		}
	}
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
		d.Enum().NewNameEvent(&Request{
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
