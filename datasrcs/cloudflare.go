// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/cloudflare/cloudflare-go"
)

// Cloudflare is the Service that handles access to the Cloudflare data source.
type Cloudflare struct {
	service.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

// NewCloudflare returns he object initialized, but not yet started.
func NewCloudflare(sys systems.System) *Cloudflare {
	c := &Cloudflare{
		SourceType: requests.API,
		sys:        sys,
	}

	c.BaseService = *service.NewBaseService(c, "Cloudflare")
	return c
}

// Description implements the Service interface.
func (c *Cloudflare) Description() string {
	return c.SourceType
}

// OnStart implements the Service interface.
func (c *Cloudflare) OnStart() error {
	c.creds = c.sys.Config().GetDataSourceConfig(c.String()).GetCredentials()

	if c.creds == nil || c.creds.Key == "" {
		c.sys.Config().Log.Printf("%s: API key data was not provided", c.String())
	}

	c.SetRateLimit(2)
	return nil
}

// OnRequest implements the Service interface.
func (c *Cloudflare) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.DNSRequest); ok {
		c.dnsRequest(ctx, req)
		c.CheckRateLimit()
	}
}

func (c *Cloudflare) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if c.creds == nil || c.creds.Key == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", c.String(), req.Domain))

	api, err := cloudflare.NewWithAPIToken(c.creds.Key)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", c.String(), err))
	}

	zones, err := api.ListZones(req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", c.String(), err))
	}

	for _, zone := range zones {
		records, err := api.DNSRecords(zone.ID, cloudflare.DNSRecord{})
		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", c.String(), err))
		}

		for _, record := range records {
			if d := cfg.WhichDomain(record.Name); d != "" {
				bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
					Name:   record.Name,
					Domain: req.Domain,
					Tag:    c.SourceType,
					Source: c.String(),
				})
			}
			if record.Type == "CNAME" {
				if d := cfg.WhichDomain(record.Content); d != "" {
					bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
						Name:   record.Content,
						Domain: req.Domain,
						Tag:    c.SourceType,
						Source: c.String(),
					})
				}
			}
		}
	}
}
