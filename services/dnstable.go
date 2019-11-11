// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// DNSTable is the Service that handles access to the DNSTable data source.
type DNSTable struct {
	BaseService

	SourceType string
}

// NewDNSTable returns he object initialized, but not yet started.
func NewDNSTable(sys System) *DNSTable {
	d := &DNSTable{SourceType: requests.SCRAPE}

	d.BaseService = *NewBaseService(d, "DNSTable", sys)
	return d
}

// Type implements the Service interface.
func (d *DNSTable) Type() string {
	return d.SourceType
}

// OnStart implements the Service interface.
func (d *DNSTable) OnStart() error {
	d.BaseService.OnStart()

	d.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (d *DNSTable) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	d.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, d.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", d.String(), req.Domain))

	url := d.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
			Tag:    d.SourceType,
			Source: d.String(),
		})
	}
}

func (d *DNSTable) getURL(domain string) string {
	format := "https://dnstable.com/domain/%s"

	return fmt.Sprintf(format, domain)
}
