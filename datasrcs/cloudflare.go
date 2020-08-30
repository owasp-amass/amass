// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/cloudflare/cloudflare-go"
)

// Cloudflare is the Service that handles access to the Cloudflare data source.
type Cloudflare struct {
	requests.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

// NewCloudflare returns he object initialized, but not yet started.
func NewCloudflare(sys systems.System) *Cloudflare {
	u := &Cloudflare{
		SourceType: requests.API,
		sys:        sys,
	}

	u.BaseService = *requests.NewBaseService(u, "Cloudflare")
	return u
}

// Type implements the Service interface.
func (u *Cloudflare) Type() string {
	return u.SourceType
}

// OnStart implements the Service interface.
func (u *Cloudflare) OnStart() error {
	u.BaseService.OnStart()

	u.creds = u.sys.Config().GetDataSourceConfig(u.String()).GetCredentials()
	if u.creds == nil || u.creds.Key == "" {
		u.sys.Config().Log.Printf("%s: API key data was not provided", u.String())
	}

	u.SetRateLimit(500 * time.Millisecond)
	return nil
}

// OnDNSRequest implements the Service interface.
func (u *Cloudflare) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if u.creds == nil || u.creds.Key == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	u.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, u.String())
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", u.String(), req.Domain))

	api, err := cloudflare.NewWithAPIToken(u.creds.Key)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", u.String(), err))
	}

	zones, err := api.ListZones(req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", u.String(), err))
	}

	for _, zone := range zones {
		records, err := api.DNSRecords(zone.ID, cloudflare.DNSRecord{})
		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", u.String(), err))
		}

		for _, record := range records {
			if d := cfg.WhichDomain(record.Name); d != "" {
				bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
					Name:   record.Name,
					Domain: req.Domain,
					Tag:    u.SourceType,
					Source: u.String(),
				})
			}
			if record.Type == "CNAME" {
				if d := cfg.WhichDomain(record.Content); d != "" {
					bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
						Name:   record.Content,
						Domain: req.Domain,
						Tag:    u.SourceType,
						Source: u.String(),
					})
				}
			}
		}
	}
}
