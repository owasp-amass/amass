// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// DNSTable is the Service that handles access to the DNSTable data source.
type DNSTable struct {
	services.BaseService

	SourceType string
}

// NewDNSTable returns he object initialized, but not yet started.
func NewDNSTable(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *DNSTable {
	d := &DNSTable{SourceType: requests.SCRAPE}

	d.BaseService = *services.NewBaseService(d, "DNSTable", cfg, bus, pool)
	return d
}

// OnStart implements the Service interface
func (d *DNSTable) OnStart() error {
	d.BaseService.OnStart()

	go d.processRequests()
	return nil
}

func (d *DNSTable) processRequests() {
	for {
		select {
		case <-d.Quit():
			return
		case req := <-d.DNSRequestChan():
			if d.Config().IsDomainInScope(req.Domain) {
				d.executeQuery(req.Domain)
			}
		case <-d.AddrRequestChan():
		case <-d.ASNRequestChan():
		case <-d.WhoisRequestChan():
		}
	}
}

func (d *DNSTable) executeQuery(domain string) {
	re := d.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	d.SetActive()
	url := d.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Config().Log.Printf("%s: %s: %v", d.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		d.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
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
